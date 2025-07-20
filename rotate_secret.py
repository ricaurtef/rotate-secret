# rotate_secret.py
# A modern, standalone rotation script using psycopg2.

import boto3
import json
import logging
import os
import psycopg2
from psycopg2 import sql

# Set up logging for CloudWatch
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Main Lambda handler for rotating a PostgreSQL secret using psycopg2.
    This function is compatible with modern PostgreSQL and scram-sha-256.
    """
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    service_client = boto3.client('secretsmanager')

    # Ensure the secret version is correctly staged
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error(f"Secret {arn} is not enabled for rotation.")
        raise ValueError(f"Secret {arn} is not enabled for rotation.")

    versions = metadata['VersionIdsToStages']
    if token not in versions:
        raise ValueError(f"Secret version {token} has no stage for rotation of secret {arn}.")
    if "AWSCURRENT" in versions[token]:
        logger.info(f"Secret version {token} already set as AWSCURRENT for secret {arn}.")
        return
    elif "AWSPENDING" not in versions[token]:
        raise ValueError(f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}.")

    logger.info(f"Executing step {step} for secret {arn}.")

    if step == "createSecret":
        create_secret(service_client, arn, token)
    elif step == "setSecret":
        set_secret(service_client, arn, token)
    elif step == "testSecret":
        test_secret(service_client, arn, token)
    elif step == "finishSecret":
        finish_secret(service_client, arn, token)
    else:
        raise ValueError(f"Invalid step parameter {step} for secret {arn}")

def create_secret(service_client, arn, token):
    """Generate a new secret password."""
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")

    try:
        # See if the pending version already exists
        get_secret_dict(service_client, arn, "AWSPENDING", token)
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        # Generate a new password
        exclude_characters = os.environ.get('EXCLUDE_CHARACTERS', '/@"\'\\')
        passwd = service_client.get_random_password(ExcludeCharacters=exclude_characters)
        current_dict['password'] = passwd['RandomPassword']

        # Put the secret
        service_client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=json.dumps(current_dict),
            VersionStages=['AWSPENDING']
        )
        logger.info(f"createSecret: Successfully put secret for ARN {arn} and version {token}.")

def set_secret(service_client, arn, token):
    """Set the pending secret in the database."""
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)

    conn = None
    try:
        # Connect to the database with the old (current) password
        conn = get_connection(current_dict)
        with conn.cursor() as cur:
            # Use psycopg2's sql.Identifier for safe quoting
            user_identifier = sql.Identifier(pending_dict['username'])
            # Use placeholder for the password to prevent SQL injection
            query = sql.SQL("ALTER USER {user} WITH PASSWORD %s").format(user=user_identifier)
            cur.execute(query, (pending_dict['password'],))
            logger.info(f"setSecret: Successfully set password for user {pending_dict['username']} in PostgreSQL.")
        conn.commit()
    except Exception as e:
        logger.error(f"setSecret: Failed to set new password. Error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def test_secret(service_client, arn, token):
    """Test the pending secret against the database."""
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)
    conn = None
    try:
        # Connect with the new password
        conn = get_connection(pending_dict)
        logger.info(f"testSecret: Successfully connected to PostgreSQL with pending secret for {arn}.")
    except Exception as e:
        logger.error(f"testSecret: Failed to connect with pending secret. Error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def finish_secret(service_client, arn, token):
    """Finish the rotation by marking the pending secret as current."""
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version, stages in metadata['VersionIdsToStages'].items():
        if 'AWSCURRENT' in stages:
            if version == token:
                logger.info(f"finishSecret: Version {version} already marked as AWSCURRENT for {arn}")
                return
            current_version = version
            break

    service_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage='AWSCURRENT',
        MoveToVersionId=token,
        RemoveFromVersionId=current_version
    )
    logger.info(f"finishSecret: Successfully set AWSCURRENT stage to version {token} for secret {arn}.")

def get_secret_dict(service_client, arn, stage, token=None):
    """Gets the secret dictionary corresponding to the secret arn, stage, and token."""
    if token:
        secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)
    return json.loads(secret['SecretString'])

def get_connection(secret_dict):
    """Establishes a connection to the PostgreSQL database using psycopg2."""
    try:
        return psycopg2.connect(
            host=secret_dict['host'],
            port=secret_dict.get('port', 5432),
            dbname=secret_dict.get('dbname', 'postgres'),
            user=secret_dict['username'],
            password=secret_dict['password'],
            connect_timeout=5,
            sslmode='prefer'  # 'prefer' will use SSL if available, but not fail if not. Change to 'require' for strict SSL.
        )
    except psycopg2.Error as e:
        logger.error(f"Database connection failed: {e}")
        raise
