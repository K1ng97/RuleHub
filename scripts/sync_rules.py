import yaml
import subprocess
import os
import shutil
import sys
import json
from datetime import datetime

# Ensure we are in the repository root directory
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
os.chdir(repo_root)

CONFIG_FILE = 'config.yml'
TEMP_DIR_BASE = '/tmp/sync_clones'
COMMIT_MESSAGE = "Automated sync: Update rules from configured sources"
PR_TITLE = "Automated Rule Sync Update"

def run_command(command, cwd=None):
    """Runs a shell command and checks for errors."""
    print(f"Running command: {' '.join(command)}")
    try:
        # Use capture_output=True and text=True for easier output handling
        result = subprocess.run(
            command,
            check=True,        # Raise CalledProcessError if command returns non-zero exit status
            cwd=cwd,
            capture_output=True, # Capture stdout and stderr
            text=True          # Decode stdout and stderr as text
        )
        print("STDOUT:\n", result.stdout)
        # print("STDERR:\n", result.stderr) # Uncomment for verbose error output
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print("STDOUT:\n", e.stdout)
        print("STDERR:\n", e.stderr)
        sys.exit(f"Command failed: {' '.join(command)}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(f"Unexpected error during command execution: {' '.join(command)}")


def read_config(config_path):
    """Reads the YAML configuration file."""
    if not os.path.exists(config_path):
        sys.exit(f"Error: Config file not found at {config_path}")
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def sync_repository(repo_config):
    """Syncs a single repository based on config."""
    name = repo_config['name']
    url = repo_config['url']
    source_dir = repo_config['source_dir']
    target_dir = repo_config['target_dir']
    
    # 检查版本元数据文件
    version_file = os.path.join(repo_root, 'rules', 'version_metadata.json')
    if os.path.exists(version_file):
        with open(version_file, 'r') as f:
            version_data = json.load(f)
        
        # 获取远程仓库最新commit
        remote_commit = run_command(['git', 'ls-remote', url, 'HEAD'], cwd=repo_root).split()[0]
        
        # 检查是否有更新
        if name in version_data['repositories'] and version_data['repositories'][name]['last_commit'] == remote_commit:
            print(f"{name}规则仓库没有更新，跳过同步")
            return

    temp_clone_path = os.path.join(TEMP_DIR_BASE, name)
    source_rules_path = os.path.join(temp_clone_path, source_dir)
    target_rules_path = os.path.join(repo_root, target_dir)

    print(f"\n--- Syncing {name} from {url} ---")
    print(f"Source dir: {source_dir}")
    print(f"Target dir: {target_dir}")

    # 1. Clean up previous temporary clone if it exists
    if os.path.exists(temp_clone_path):
        print(f"Cleaning up existing temporary clone: {temp_clone_path}")
        shutil.rmtree(temp_clone_path)

    # 2. Shallow clone the source repository
    print(f"Cloning source repository into {temp_clone_path}...")
    run_command(['git', 'clone', '--depth', '1', url, temp_clone_path])

    # 3. Ensure the target directory exists in this repository
    os.makedirs(target_rules_path, exist_ok=True)
    print(f"Ensured target directory exists: {target_rules_path}")


    # 4. Use rsync to sync the source directory content to the target directory
    # IMPORTANT: The trailing slash on the source path is crucial for rsync
    # It means "copy the contents of this directory", not the directory itself.
    source_for_rsync = source_rules_path + '/'
    target_for_rsync = target_rules_path + '/'

    print(f"Syncing content from {source_for_rsync} to {target_for_rsync} using rsync...")
    # -a: archive mode (preserves permissions, times, etc.)
    # -v: verbose
    # --delete: delete files in the target that are not in the source
    # --exclude='.git': Exclude .git directories in case source_dir was repo root (less likely here)
    run_command(['rsync', '-av', '--delete', '--exclude', '.git', source_for_rsync, target_for_rsync])

    print(f"--- Finished syncing {name} ---")
    
    # 更新版本元数据
    version_file = os.path.join(repo_root, 'rules', 'version_metadata.json')
    if os.path.exists(version_file):
        with open(version_file, 'r+') as f:
            version_data = json.load(f)
            # 获取远程仓库最新commit
            remote_commit = run_command(['git', 'ls-remote', url, 'HEAD'], cwd=repo_root).split()[0]
            # 更新元数据
            version_data['repositories'][name] = {
                'url': url,
                'last_sync': datetime.now().isoformat(),
                'last_commit': remote_commit
            }
            f.seek(0)
            json.dump(version_data, f, indent=2)
            f.truncate()
            print(f"Updated version metadata for {name}")


def main():
    print("Starting rule synchronization...")
    
    # 确保导入json模块
    import json

    # Ensure rsync is available (should be on ubuntu-latest)
    try:
        run_command(['rsync', '--version'])
    except:
        sys.exit("Error: rsync command not found. Cannot proceed.")

    # Ensure temporary directory base exists
    os.makedirs(TEMP_DIR_BASE, exist_ok=True)

    # Read the configuration
    config = read_config(CONFIG_FILE)
    if not config or 'repositories' not in config:
        sys.exit(f"Error: Config file {CONFIG_FILE} is empty or missing 'repositories' section.")

    # Sync each configured repository
    for repo_config in config.get('repositories', []):
        sync_repository(repo_config)

    # --- Git operations on *this* repository ---
    print("\n--- Checking for changes in this repository ---")

    # Add all potentially changed files in the target directories
    # This will stage new, modified, and deleted files detected by rsync
    print("Staging all changes in configured target directories...")
    # Get all target directories from config to specifically add them
    all_target_dirs = [os.path.join(repo_root, r['target_dir']) for r in config.get('repositories', [])]
    # Use git add on the specific target directories
    run_command(['git', 'add'] + all_target_dirs)


    # Check if there are any staged changes
    status_output = run_command(['git', 'status', '--porcelain'])

    if not status_output:
        print("No changes detected. Exiting.")
        # Clean up the temporary directory base
        print(f"Cleaning up temporary clone base: {TEMP_DIR_BASE}")
        shutil.rmtree(TEMP_DIR_BASE)
        sys.exit(0) # Exit successfully as no changes means nothing to do

    print("Changes detected. Creating commit and Pull Request.")
    print("Git Status:\n", status_output)

    # Generate a unique branch name
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    new_branch_name = f'auto-sync-rules-{timestamp}'
    print(f"Creating new branch: {new_branch_name}")

    # Get the current branch name (should be the one checked out by actions/checkout, usually main)
    current_branch = run_command(['git', 'rev-parse', '--abbrev-ref', 'HEAD']).strip()
    print(f"Current branch before checkout: {current_branch}")


    # Create and switch to the new branch
    # Use `git checkout -b` directly creates the branch and switches to it
    run_command(['git', 'checkout', '-b', new_branch_name])
    print(f"Switched to new branch: {new_branch_name}")


    # Commit the changes
    print("Committing changes...")
    run_command(['git', 'commit', '-m', COMMIT_MESSAGE])


    # Push the new branch to the origin
    print(f"Pushing branch {new_branch_name} to origin...")
    # The GITHUB_TOKEN from the workflow environment will be used for authentication
    # by the git command line when running inside GitHub Actions.
    run_command(['git', 'push', 'origin', new_branch_name])

    print("Push successful.")

    # Clean up the temporary directory base
    print(f"Cleaning up temporary clone base: {TEMP_DIR_BASE}")
    shutil.rmtree(TEMP_DIR_BASE)

    # Output the branch name so the next step (Create Pull Request) can use it
    # This uses GitHub Actions step output format
    # print(f"::set-output name=new_branch_name::{new_branch_name}") # Deprecated
    # Use environment files instead for GitHub Actions >= 20.04 runner
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            print(f'new_branch_name={new_branch_name}', file=f)
    else:
        print(f"::set-output name=new_branch_name::{new_branch_name}")


    print("Rule synchronization script finished.")
    # Script exits successfully, next step (Create PR) will run

if __name__ == "__main__":
    main()