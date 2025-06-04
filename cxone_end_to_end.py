import requests
import time
import datetime
# import os
import pandas as pd
import ast

from dataclasses import dataclass

@dataclass
class CxOneConfig:
    tenant: str
    token: str
    project_name: str
    region: str = "anz"
    repo_url: str = "https://github.com/WebGoat/WebGoat"
    branch: str = "main"

class CxOneBasicScan:
    def __init__(self, config: CxOneConfig):
        self.config = config
        self.tenant = config.tenant
        self.token = config.token
        self.project_name = config.project_name
        self.region = config.region
        self.repo_url = config.repo_url
        self.branch = config.branch
        self.access_token = None
        self.headers = None
        self.project_id = None
        self.scan_id = None
        self.base_url = f"https://{self.region}.ast.checkmarx.net/api"
        self.df_sast_report = None
        self.report_id = None
        self.df_sast = None
        self.df_sast_enriched = None
        self.df_sast_predicates = None
        self.df_sast_predicates_enriched = None

        # Debug CSV file for enriched findings
    DEBUG_FINDING_ENRICHED_CSV = "debug_finding_enriched.csv"

    def authenticate(self):
        url = f"https://{self.region}.iam.checkmarx.net/auth/realms/{self.tenant}/protocol/openid-connect/token"
        payload = {
            "grant_type": "refresh_token",
            "client_id": "ast-app",
            "refresh_token": self.token
        }
        response = requests.post(url, data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"})
        if response.status_code == 200:
            self.access_token = response.json().get("access_token")
            self.headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            print("✅ Authenticated successfully.")
        else:
            raise Exception(f"❌ Auth failed: {response.status_code}\n{response.text}")

    def get_or_create_project(self):
        url = f"{self.base_url}/projects"
        response = requests.get(url, headers=self.headers)
        if response.status_code != 200:
            raise Exception(f"Failed to get projects. {response.status_code}: {response.text}")
        projects = response.json().get("projects", [])
        for p in projects:
            if p["name"].lower() == self.project_name.lower():
                self.project_id = p["id"]
                print(f"ℹ️ Project already exists: {self.project_name} (ID: {self.project_id})")
                return
        # If not found, create
        payload = {
            "name": self.project_name,
            "description": "Created via automation",
            "groups": [
                "defb38bc-24c7-4194-8a93-c8e6cdf165cd"
            ],
        }
        response = requests.post(url, json=payload, headers=self.headers)
        if response.status_code == 201:
            self.project_id = response.json()["id"]
            print(f"✅ Project created: {self.project_name} (ID: {self.project_id})")
        else:
            raise Exception(f"❌ Failed to create project. {response.status_code}: {response.text}")

    def start_scan(self):
        url = f"{self.base_url}/scans"
        payload = {
            "project": {"id": self.project_id},
            "type": "git",
            "handler": {
                "repoUrl": self.repo_url,
                "branch": self.branch
            },
            "config": [
                {"type": "sast", "value": {"incremental": "false"}},
                {"type": "sca", "value": {"lastSastScanTime": ""}}
            ]
        }
        response = requests.post(url, json=payload, headers=self.headers)
        if response.status_code == 201:
            self.scan_id = response.json().get("id")
            print(f"🚀 Scan started. ID: {self.scan_id}")
        else:
            raise Exception(f"❌ Failed to start scan. {response.status_code}: {response.text}")

    def wait_for_scan_completion(self, timeout=600, poll_interval=20):
        url = f"{self.base_url}/scans/{self.scan_id}"
        elapsed = 0
        while elapsed < timeout:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                status = response.json().get("status", "").lower()
                print(f"⏱ Scan status: {status}")
                if status == "completed":
                    print("✅ Scan completed successfully.")
                    return self.scan_id
                elif status in ["failed", "cancelled"]:
                    raise Exception(f"❌ Scan ended with status: {status}")
            else:
                print(f"⚠️ Failed to check scan status: {response.status_code}")
            time.sleep(poll_interval)
            elapsed += poll_interval
        raise TimeoutError("⏰ Scan did not complete in time.")

    def run(self):
        self.authenticate()
        self.get_or_create_project()
        self.start_scan()
        return self.wait_for_scan_completion()
    

    def check_report_status(self):
        """
        Check the status of the report generation using self.report_id.
        """
        if not hasattr(self, "report_id") or not self.report_id:
            raise ValueError("report_id not set.")
        url = f"{self.base_url}/reports/{self.report_id}"
        headers = self.headers.copy()
        headers["Accept"] = "application/json; version=1.0"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get("status", "")
        else:
            raise Exception(f"Failed to check report status: {response.status_code} {response.text}")


    def generate_scan_report(self, scan_id=None, project_id=None, report_name="improved-scan-report",
                             file_format="csv", report_type="cli", branch_name=None,
                             sections=None, scanners=None, email_recipients=None,
                             wait_for_ready=True, poll_interval=10, timeout=300):

        scan_id = scan_id or getattr(self, "scan_id", None)
        project_id = project_id or getattr(self, "project_id", None)

        if report_type == "email" and not email_recipients:
            raise ValueError("❌ 'email_recipients' must be provided when report_type is 'email'.")
        if not scan_id or not project_id:
            raise ValueError("❌ scan_id and project_id are required.")

        url = f"{self.base_url}/reports"
        payload = {
            "reportName": report_name,
            "fileFormat": file_format,
            "reportType": report_type,
            "data": {
                "scanId": scan_id,
                "projectId": project_id
            }
        }

        if branch_name:
            payload["data"]["branchName"] = branch_name
        if sections:
            payload["data"]["sections"] = sections
        if scanners:
            payload["data"]["scanners"] = scanners
        if report_type == "email":
            payload["data"]["email"] = email_recipients

        headers = self.headers.copy()
        headers["Accept"] = "application/json; version=1.0"

        print("📤 Sending report generation request...")
        response = requests.post(url, json=payload, headers=headers)

        if response.status_code == 202:
            self.report_id = response.json().get("reportId")
            print(f"✅ Report request submitted. Report ID: {self.report_id}")
        else:
            print(f"❌ Failed to generate report: {response.status_code}")
            print(response.text)
            return None

        # If we don't wait for readiness, return the report ID immediately
        if not wait_for_ready:
            return self.report_id

        print("⏳ Waiting for report to be ready...")
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.check_report_status()
            if status.lower() in ["ready", "completed"]:
                print("✅ Report is ready!")
                break
            elif status.lower() in ["failed", "cancelled"]:
                print(f"❌ Report generation failed: {status}")
                return None
            time.sleep(poll_interval)

        # Download report
        if self.check_report_status().lower() in ["ready", "completed"]:
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"{self.project_name}_{scan_id}_{timestamp}.{file_format}"
            report_path = self.download_report(report_id=self.report_id, filename=filename)
            if report_path and file_format == "csv":
                self.df_sast_report = pd.read_csv(report_path)
                self.df_sast_report.to_csv('sast_report.csv', index=False) # Save to CSV for further processing
                print("📊 Report saved as CSV:", report_path)
            # Optionally, handle PDF with tabula or pdfplumber if needed
            return report_path
        else:
            print("⚠️ Report not ready after timeout.")
            return None
        
    def download_report(self, report_id, filename):
        """
        Download the report file by report_id and save it locally.
        """
        url = f"{self.base_url}/reports/{report_id}/download"
        headers = self.headers.copy()
        headers["Accept"] = "application/octet-stream"

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            with open(filename, "wb") as f:
                f.write(response.content)
            print(f"📥 Report downloaded: {filename}")
            return filename
        else:
            print(f"❌ Failed to download report: {response.status_code}")
            print(response.text)
            return None
        
    def print_scan_info(self, scan_id):
        """
        Print basic scan info from scan ID.
        """
        url = f"{self.base_url}/scans/{scan_id}"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            data = response.json()
            print("📄 Scan Info:")
            print(f"  ID: {data.get('id')}")
            print(f"  Status: {data.get('status')}")
            print(f"  Created: {data.get('created')}")
            self.project_id = data.get("projectId") or data.get("project", {}).get("id")
            print(f"  Project ID: {self.project_id}")
            print(f"  Branch: {data.get('branch')}")
        else:
            print(f"❌ Failed to retrieve scan info. {response.status_code}: {response.text}")

    def bulk_update_sast_predicates(self, scan_id=None, severity="CRITICAL", state="CONFIRMED", comment="VIOLATE OWASP"):
        """
        Retrieve SAST results for a given scan, extract similarity IDs, and bulk update predicates.
        Also enriches findings with detailed fields and saves to self.df_sast.
        """

        scan_id = scan_id or getattr(self, "scan_id", None)
        if not hasattr(self, "project_id") or not scan_id:
            raise ValueError("Both project_id and scan_id must be set.")

        url = f"{self.base_url}/sast-results/?scan-id={scan_id}&include-nodes=true&apply-predicates=true&limit=1000"
        headers = self.headers.copy()
        headers["Accept"] = "application/json; version=1.0"

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"ERROR: Failed to retrieve SAST results. Status code: {response.status_code}")
            print(response.text)
            return

        debug_finding = response.json()['results']
        df_finding = pd.DataFrame(debug_finding)
        df_finding.to_csv('debug_finding.csv', index=False)
        print("🔍 Unique ID count:", df_finding["id"].nunique())
        print("🔍 Total rows before explode:", len(df_finding))
        print("🧪 Columns in df_finding:", df_finding.columns.tolist())
        print("🧪 Sample rows from df_finding:")
        print(df_finding.head())
        print("🔢 Row count of df_finding before explode:", len(df_finding))

        # Drop rows where "id" is null before further processing
        df_finding = df_finding[df_finding["id"].notnull()]

        # Parse nodes and extract only the primary (first) node per finding, preserving one row per finding
        def safe_parse(x):
            if isinstance(x, str):
                return ast.literal_eval(x)
            return x

        df_finding["parsed_nodes"] = df_finding["nodes"].apply(safe_parse)
        df_finding["primary_node"] = df_finding["parsed_nodes"].apply(lambda x: x[0] if isinstance(x, list) and x else {})
        print("🔢 Row count (no explode, single primary_node per finding):", len(df_finding))

        # Add block to ensure similarityId is preserved correctly (with debug)
        if "similarityID" in df_finding.columns:
            print("✅ 'similarityID' found in df_finding. Propagating to main data...")
            # Only include records with non-null similarityID, id, and queryName values (extra safeguard)
            df_similarity_map = df_finding[
                df_finding["similarityID"].notnull() &
                df_finding["id"].notnull() &
                df_finding["queryName"].notnull()
            ].drop_duplicates(subset=["id"])[["id", "similarityID", "queryName"]]
            df_similarity_map = df_similarity_map.rename(columns={"similarityID": "similarityId"})
            print("🔍 Duplicated IDs in similarity map:", df_similarity_map.duplicated(subset=["id"]).sum())
            print("🧭 Mapping base (df_similarity_map):", df_similarity_map.drop_duplicates(subset=["similarityId", "queryName"]).shape[0])
            print("🔍 Distinct (similarityID, queryName) pairs in df_similarity_map:", df_similarity_map[["similarityId", "queryName"]].drop_duplicates().shape[0])
            print("🧭 Index preview:", df_similarity_map["id"].tolist()[:5])
            df_finding = df_finding.merge(
                df_similarity_map,
                how="left", on=["id"]
            )
            # Resolve queryName after merge
            if "queryName_y" in df_finding.columns:
                df_finding["queryName"] = df_finding["queryName_y"]
            elif "queryName_x" in df_finding.columns:
                df_finding["queryName"] = df_finding["queryName_x"]
            # Clean up potential duplicated columns
            df_finding.drop(columns=[col for col in ["queryName_x", "queryName_y"] if col in df_finding.columns], inplace=True)
            print("📋 Columns after merge:", df_finding.columns.tolist())
            print("🔁 Completed merging similarityId and queryName")
            print("🔢 Row count after merge:", len(df_finding))
            print("🔢 Number of non-null similarityId values:", df_finding['similarityId'].notnull().sum())
            print("🔍 Distinct (similarityId, queryName) after merge:", df_finding[["similarityId", "queryName"]].drop_duplicates().shape[0])
            debug_columns = [col for col in ["similarityId", "queryName", "SrcFileName", "Line"] if col in df_finding.columns]
            print("🧪 Sample enriched rows:", df_finding[debug_columns].head())
        else:
            print("⚠️ Column 'similarityID' not found in df_finding.")

        # Extract node fields from the primary_node column
        df_finding["SrcFileName"] = df_finding["primary_node"].apply(lambda x: x.get("fileName"))
        df_finding["Line"] = df_finding["primary_node"].apply(lambda x: x.get("line"))
        df_finding["Column"] = df_finding["primary_node"].apply(lambda x: x.get("column"))
        df_finding["NodeName"] = df_finding["primary_node"].apply(lambda x: x.get("name"))
        # Ensure necessary columns exist before dropping duplicates
        required_columns = ["similarityId", "queryName"]
        missing_columns = [col for col in required_columns if col not in df_finding.columns]
        if missing_columns:
            print(f"⚠️ Cannot drop duplicates. Missing columns: {missing_columns}")
            df_finding.to_csv("debug_missing_columns.csv", index=False)
            return
        # Debug: Row count before dropping duplicates
        print(f"🔁 Row count before drop_duplicates: {len(df_finding)}")
        # Print unique (id, similarityId, queryName, SrcFileName, Line, Column) tuples before dropping duplicates
        print(f"🔍 Unique (id, similarityId, queryName, SrcFileName, Line, Column) tuples before drop: {df_finding[['id', 'similarityId', 'queryName', 'SrcFileName', 'Line', 'Column']].drop_duplicates().shape[0]}")

        # Drop duplicates keeping the first row per unique combination (excluding 'id')
        df_merged = df_finding
        df_final = df_merged.drop_duplicates(
            subset=['similarityId', 'queryName', 'SrcFileName', 'Line', 'Column', 'NodeName', 'resultHash'],
            keep='first'
        )
        print("🧠 Unique finding IDs before dedup:", df_merged['id'].nunique())
        print("🧠 Unique finding IDs after dedup:", df_final['id'].nunique())
        print(f"🔁 Number of duplicates removed: {len(df_merged) - len(df_final)}")
        print(f"🔍 Row count after drop_duplicates: {len(df_final)}")
        # Save the enriched version (single row per finding)
        df_final.to_csv(self.DEBUG_FINDING_ENRICHED_CSV, index=False)
        print(f"🧾 Final row count written to CSV: {len(df_final)}")
    

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--region", default="anz")
    parser.add_argument("--repo-url", default="https://github.com/WebGoat/WebGoat")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--scan-id", help="If provided, only fetch scan info without triggering a new scan")
    args = parser.parse_args()

    config = CxOneConfig(
        tenant=args.tenant,
        token=args.token,
        project_name=args.project_name,
        region=args.region,
        repo_url=args.repo_url,
        branch=args.branch
    )
    scanner = CxOneBasicScan(config)
    scanner.authenticate()
    scanner.scan_id = args.scan_id
    if args.scan_id:
        scanner.print_scan_info(scan_id=args.scan_id)
        scanner.bulk_update_sast_predicates(scan_id=args.scan_id)
        scanner.generate_scan_report(scan_id=args.scan_id, file_format="csv", report_type="cli")
    else:
        scanner.get_or_create_project()
        scanner.start_scan()
        scan_id = scanner.wait_for_scan_completion()
        scanner.scan_id = scan_id
        scanner.bulk_update_sast_predicates(scan_id=scan_id)
        scanner.generate_scan_report(scan_id=scan_id, file_format="csv", report_type="cli")
        print(f"🎯 Finished. Scan ID: {scan_id}")