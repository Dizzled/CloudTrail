import boto3
import json
import re
import os

# Get AWS credentials from environment variables
access_key = os.environ.get('AWS_ACCESS_KEY_ID')
secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
region = 'us-east-1'

# Specify the AWS CloudTrail name
trail_name = 'my-cloudtrail'

# Specify the pattern for each sensitive data type
access_key_pattern = re.compile(r'AKIA[0-9A-Z]{16}')
temporary_access_key_pattern = re.compile(r'ASIA[0-9A-Z]{16}')
mfa_seed_pattern = re.compile(r'[0-9A-Za-z+/]{40}')
api_key_pattern = re.compile(r'[0-9a-zA-Z]{30,}')
otp_pattern = re.compile(r'[0-9]{6}')
push_notification_key_pattern = re.compile(r'[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}')
symmetric_key_pattern = re.compile(r'[0-9a-zA-Z/+]{44}={0,2}')
asymmetric_key_pattern = re.compile(r'-----BEGIN (PRIVATE|PUBLIC) KEY-----')
nonce_pattern = re.compile(r'[0-9a-zA-Z/+]{22}==')
s3_presigned_url_pattern = re.compile(r'https://.+\.amazonaws\.com/.+&X-Amz-Signature=.+')
sso_federation_pattern = re.compile(r'SAMLResponse=.+|SAMLRequest=.+|RelayState=.+|AWSAccessKeyId=.+|Signature=.+|TokenCode=.+')

# Create a CloudTrail client with the credentials
client = boto3.client('cloudtrail', region_name=region, aws_access_key_id=access_key, aws_secret_access_key=secret_key)

# Get the latest CloudTrail events
response = client.lookup_events(LatestTime='2023-04-12T00:00:00Z')

# Loop through the events and check for sensitive data
for event in response['Events']:
    event_name = event['EventName']
    resources = event.get('Resources')
    if resources:
        resource_names = [resource['ResourceName'] for resource in resources]
    else:
        resource_names = []

    # Check the CloudTrail event for each sensitive data type
    if access_key_pattern.search(json.dumps(event)):
        print(f"Sensitive data found in CloudTrail event: {event_name}, resources: {resource_names}, access key")
    if temporary_access_key_pattern.search(json.dumps(event)):
        print(f"Sensitive data found in CloudTrail event: {event_name}, resources: {resource_names}, temporary access key")
    if mfa_seed_pattern.search(json.dumps(event)):
        print(f"Sensitive data found in CloudTrail event: {event_name}, resources: {resource_names}, MFA seed")
    if api_key_pattern.search(json.dumps(event)):
        print(f"Sensitive data found in CloudTrail event: {event_name}, resources: {resource_names}, API key")
    if otp_pattern.search(json.dumps(event)):
        print(f"Sensitive data found in CloudTrail event: {event_name}, resources: {resource_names}, one-time password")
    if push_notification_key_pattern.search(json.dumps(event)):
        print(f"Sensitive data found in CloudTrail event: {event_name}, resources: {resource_names}, push notification key")
    if symmetric_key_pattern.search(json.dumps(event)):
        print(f"Sensitive data found in CloudTrail event: {event_name}, resources: {resource_names}, symmetric key")
    if asymmetric_key_pattern.search(json.dumps(event)):
        print(f"Sensitive data found in CloudTrail event: {event_name}, resources: {resource_names}, asymmetric key")
    if nonce_pattern.search(json.dumps(event)):
        print(f"Sensitive data found in CloudTrail event: {event_name}, resources: {resource_names}, nonce")
    if s3_presigned_url_pattern.search(json.dumps(event)):
        print(f"Sensitive data found in CloudTrail event: {event_name}, resources: {resource_names}, S3 presigned URL")
    if sso_federation_pattern.search(json.dumps(event)):
        print(f"Sensitive data found in CloudTrail event: {event_name}, resources: {resource_names}, SSO federation")

    