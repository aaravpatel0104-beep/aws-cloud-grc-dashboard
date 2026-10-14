import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from botocore.exceptions import NoCredentialsError, ClientError

load_dotenv()

from modules.iam_auditor import check_iam_security
from modules.s3_auditor import check_s3_security
from modules.ec2_auditor import check_ec2_security
from modules.pdf_generator import generate_pdf_report

st.set_page_config(page_title="Cloud GRC Posture Dashboard", layout="wide")

st.title("🛡️ Cloud Security & GRC Posture Dashboard")
st.markdown("Automated configuration audit mapped to **NIST CSF 2.0** and **CIS AWS Foundations**.")

if st.button("Run Compliance Audit"):
    try:
        with st.spinner("Querying live AWS APIs via Boto3..."):
            iam_results = check_iam_security()
            s3_results = check_s3_security()
            ec2_results = check_ec2_security()
            all_results = iam_results + s3_results + ec2_results
            st.session_state['audit_df'] = pd.DataFrame(all_results)
    except NoCredentialsError:
        st.error("AWS credentials not found. Verify your keys inside the .env file.")
        st.stop()
    except ClientError as e:
        st.error(f"AWS API Access Error: {e}")
        st.stop()

if 'audit_df' in st.session_state:
    df = st.session_state['audit_df']
    total_checks = len(df)
    passed_checks = len(df[df['Status'] == 'PASS'])
    failed_checks = len(df[df['Status'] == 'FAIL'])
    compliance_score = int((passed_checks / total_checks) * 100) if total_checks > 0 else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Overall Compliance", f"{compliance_score}%")
    col2.metric("Total Controls Audited", total_checks)
    col3.metric("Passed Controls", passed_checks)
    col4.metric("Failed Controls (Action Req.)", failed_checks, delta_color="inverse")

    st.divider()

    status_filter = st.selectbox("Filter by Status", ["ALL", "FAIL", "PASS"])
    display_df = df if status_filter == "ALL" else df[df['Status'] == status_filter]

    st.subheader("Control Audit Findings")
    st.dataframe(display_df, use_container_width=True)

    # Export Buttons
    c_csv, c_pdf = st.columns(2)
    with c_csv:
        csv_data = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📄 Download Audit Results (.CSV)",
            data=csv_data,
            file_name="aws_grc_audit_report.csv",
            mime="text/csv",
            use_container_width=True
        )
    with c_pdf:
        pdf_buffer = generate_pdf_report(df, compliance_score)
        st.download_button(
            label="📑 Download Executive Audit Report (.PDF)",
            data=pdf_buffer,
            file_name="aws_grc_executive_report.pdf",
            mime="application/pdf",
            use_container_width=True
        )
