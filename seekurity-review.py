#!/usr/bin/env python3
import ollama
import sys
import json
import base64
import os
import requests
from typing import Any
from datetime import datetime

def decode_base64_to_text(base64_string):
    decoded_bytes = base64.b64decode(base64_string)
    return decoded_bytes.decode('utf-8')

def request_file_content(file_url):
    headers = {
        'Authorization': f'token {gh_pat}',
        'Accept': 'application/vnd.github.v3+json'
    }
    direct_path_file = requests.get(file_url, headers=headers).json()
    return decode_base64_to_text(direct_path_file['content'])

def get_github_repo_tree(gh_org_repo, branch):
    headers = {
        'Authorization': f'token {gh_pat}',
        'Accept': 'application/vnd.github.v3+json'
    }
    try:
        response = requests.get(f'https://api.github.com/repos/{gh_org_repo}/git/trees/{branch}?recursive=true', headers=headers)
        return response
    except requests.exceptions.RequestException as e:
        print(f'Request error: {e}')
        return None

def generate_directory_path() -> str:
    """
    Generates a directory path based on the current date.
    
    Example:
        If the current date is October 10, 1999, it will return:
        'cx-scan/sast/1999/oct/10/'
    
    Returns:
        str: The formatted directory path.
    """
    today = datetime.now()
    year = today.strftime("%Y")
    month = today.strftime("%b").lower()
    day = today.strftime("%d")
    path = f"cx-scan/sast/{year}/{month}/{day}"
    return path

def commit_file_upstream(
    token: str,
    org: str,
    repo_name: str,
    file_name: str,
    file_content: str,
    commit_message: str,
    branch: str = "main"
) -> None:
    """
    Creates a new file in a GitHub repository using the REST API.
    
    Parameters:
        token (str): GitHub personal access token.
        org (str): Organization or user name.
        repo_name (str): Repository name.
        file_name (str): Path and name of the file to be created.
        file_content (str): Content to write into the file.
        commit_message (str): Commit message.
        branch (str, optional): Branch to commit to. Default is "main".
    
    Exceptions:
        Exception: If the request fails or file creation fails.
    """
    url = f"https://api.github.com/repos/{org}/{repo_name}/contents/{file_name}"
    encoded_content = base64.b64encode(file_content.encode("utf-8")).decode("utf-8")
    payload: dict[str, Any] = {
        "message": commit_message,
        "content": encoded_content,
        "branch": branch
    }
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    response = requests.put(url, headers=headers, json=payload)
    
    if response.status_code == 201:
        print(f"[+] File '{file_name}' successfully added to repo '{repo_name}' under organization '{org}'.")
    else:
        try:
            error_info = response.json()
            error_message = error_info.get("message", "Unknown error")
        except json.JSONDecodeError:
            error_message = response.text
        
        raise Exception(f"[-] Failed to add file. Code: {response.status_code}. Message: {error_message}")

def analyze_code_review(source_code: str, language: str, file_name: str, vulnerability_description: str):
    """
    Analyzes a given source code to determine whether the reported vulnerability
    is a valid security risk or a false positive, displaying the reasoning step by step.
    """
    
    prompt = f"""
    You are a cybersecurity expert with extensive experience in {language} secure code reviews. Your objective is to thoroughly analyze the provided source code and determine if the reported vulnerability is legitimate or a false positive.
    Reported Vulnerability: {vulnerability_description}
    Source Code file ({file_name}):
    ```
    {source_code}
    ```
    Cybersecurity expert secure code review steps:
    1. Understanding the Code.
    - Analyze the structure of the source code in isolation.
    - Verify whether the vulnerability is intrinsic to the code, even outside the general context of the application.
    - Identify whether there are protection mechanisms implemented to mitigate the specific vulnerability.
    2. Vulnerability Assessment.
    - Based on the analyzed code, determine whether the vulnerability is actually exploitable.
    - Evaluate whether the vulnerability applies to the context of the code or whether the code is not actually exposed to the indicated risk.
    3. Recommendations and Mitigations
    - If the vulnerability is valid, explain the reason in a technical and objective manner.
    - If it is a false positive, justify why it cannot be exploited in a technical and objective manner.
    - If applicable, provide a secure fix to eliminate or mitigate the vulnerability.
    - If applicable, suggest good security practices to avoid similar issues in the future.

    Output Format:
    ```
    # Secure code review report

    Vulnerability: {vulnerability_description}
    File: {file_name}
    language: {language}
    Status: [Valid / False Positive]
    Analysis:
    [Detailed explanation of whether the issue exists and its impact.]

    Recommendation:
    [Suggested fix or secure coding recommendation.]

    ```
    """

    stream = ollama.chat(
        model="deepseek-r1:14b",
        messages=[{"role": "user", "content": prompt}],
        stream=True,
    )

    reasoning_content = ""
    content = ""
    in_thinking = False

    for chunk in stream:
        if chunk and 'message' in chunk and chunk['message'].content:
            chunk_content = chunk['message'].content
            sys.stdout.write(chunk_content)
            sys.stdout.flush()
            if chunk_content.startswith('<think>'):
                in_thinking = True
            elif chunk_content.startswith('</think>'):
                in_thinking = False
            else:
                if in_thinking:
                    reasoning_content += chunk_content
                else:
                    content += chunk_content

    print("\n\nSecure code review (think):", reasoning_content)
    print("\nSecure code review (answer):", content)
    return reasoning_content, content

if __name__ == "__main__":

    gh_pat = os.getenv('GH_PAT')
    ORGANIZATION = os.getenv('GH_ORG', 'usrbinbrain')
    REPO = os.getenv('GH_REPO', 'seekurity-review')
    branch_name = os.getenv('BRANCH', 'main')
    
    if gh_pat:
        repo_name = f"{ORGANIZATION}/{REPO}"
        date_to_dir = generate_directory_path()
        fullpath_input_file = f"{date_to_dir}/cx-sast-output.json"
        gh_repo_tree = get_github_repo_tree(repo_name, branch_name)
        repo_tree_obj = gh_repo_tree.json()
        for item in repo_tree_obj['tree']:
            if item['path'] == fullpath_input_file:
                file_url = item['url']
                print("-----------------------------------------------------------")
                print(f"[+] Input file found in upstream repo : {item['path']}")
                print("-----------------------------------------------------------")
                break

        input_json_file_content = request_file_content(file_url)
    else:
        print("-----------------------------------------------------------")
        print("[!] GH_PAT not found in environment variables, reading local file...")
        print("-----------------------------------------------------------")
        if os.path.exists('cx-sast-output.json'):
            fullpath_input_file = 'cx-sast-output.json'
            with open(fullpath_input_file, 'r') as f:
                input_json_file_content = f.read()
    
    data = json.loads(input_json_file_content)

    print("-----------------------------------------------------------")
    print(f'[+] Load OK! Starting Secure Review for {len(data)} projects...')
    print("-----------------------------------------------------------")

    for project_name in data:
        project_obj = data[project_name]
        print("-----------------------------------------------------------")
        print('Project ->', project_name)
        print("-----------------------------------------------------------")
        branch = project_obj['branch']
        scan_id = project_obj['scan_id']
        vuln_list = project_obj['vulnerabilities']
        for vuln_obj in vuln_list:
            severity = vuln_obj.get('severity', '')
            status = vuln_obj.get('status', '')
            state = vuln_obj.get('state', '')
            cwe_id = vuln_obj.get('cwe_id', '')
            query = vuln_obj.get('query', '')
            group = vuln_obj.get('group', '')
            language = vuln_obj.get('language', '')
            description = vuln_obj.get('description', '')
            description = description[:-2]
            vuln_files = vuln_obj.get('vuln_files', [])
            print("-----------------------------------------------------------")
            print(f"Vuln Description: {description}")
            print("-----------------------------------------------------------")
            for vuln_file in vuln_files:
                file_name = vuln_file.get('file_name', '')
                file_content = vuln_file.get('file_content', '')
                file_sha = vuln_file.get('file_sha', '')
                file_size = vuln_file.get('file_size', '')
                if file_name in description:
                    print(f"[!] File Name: {file_name} - file in description")
                    secure_review_think, secure_review_content = analyze_code_review(file_content, language, file_name, description)
                    vuln_file['secure_review_think'] = secure_review_think
                    vuln_file['secure_review_result'] = secure_review_content
                else:
                    print(f"[!] File Name: {file_name} - file not in description")
                    secure_review_think, secure_review_content = analyze_code_review(file_content, language, file_name, description)
                    vuln_file['secure_review_think'] = secure_review_think
                    vuln_file['secure_review_result'] = secure_review_content

    with open('output-secure-review.json', 'w') as f:
        json.dump(data, f, indent=4)
    
    print("-----------------------------------------------------------")
    print(f'[+] Secure Review Finalized! analyzed {len(data)} projects.')
    print(f"[+] Check the file output-secure-review.json for the results.")
    print("-----------------------------------------------------------")

    if gh_pat:
        fullpath_file = f"{date_to_dir}/cx-secure-review-output.json"
        FILE_PATH = fullpath_file
        FILE_CONTENT = json.dumps(data, indent=4)
        COMMIT_MESSAGE = f"Add: Secure review file {fullpath_file}"
        try:
            commit_file_upstream(
                token=gh_pat,
                org=ORGANIZATION,
                repo_name=REPO,
                file_name=FILE_PATH,
                file_content=FILE_CONTENT,
                commit_message=COMMIT_MESSAGE,
                branch=branch_name
            )
        except Exception as e:
            print(e)
