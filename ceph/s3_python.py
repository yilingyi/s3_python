import paramiko
import boto
import boto.s3.connection
def create_user(hostname, port, username, password, user_create_command):
    ssh = paramiko.SSHClient()
    key = paramiko.AutoAddPolicy()
    ssh.set_missing_host_key_policy(key)
    ssh.connect(hostname, port, username, password ,timeout=5)
    ssh.exec_command(user_create_command)

def s3_access_key(hostname, port, username, password, get_access_key):
    ssh = paramiko.SSHClient()
    key = paramiko.AutoAddPolicy()
    ssh.set_missing_host_key_policy(key)
    ssh.connect(hostname, port, username, password ,timeout=5)
    stdin, stdout, stderr = ssh.exec_command(get_access_key)
    for i in stdout.readlines():
        get_access_key = i
    return get_access_key

def s3_secret_key(hostname, port, username, password, get_secret_key):
    ssh = paramiko.SSHClient()
    key = paramiko.AutoAddPolicy()
    ssh.set_missing_host_key_policy(key)
    ssh.connect(hostname, port, username, password ,timeout=5)
    stdin, stdout, stderr = ssh.exec_command(get_secret_key)
    for i in stdout.readlines():
        get_secret_key = i
    return get_secret_key

def create_bucket(endpoint, ak, sk, bucketname):
    access_key = ak.strip()
    secret_key = sk.strip()
    # print type(access_key)
    print("access_key:" + access_key)
    print("secret_key:" + secret_key)
    conn = boto.connect_s3(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        host=endpoint,
        is_secure=False, # uncomment if you are not using ssl
        calling_format=boto.s3.connection.OrdinaryCallingFormat(),
    )
    #create a buckets
    bucket = conn.create_bucket(bucketname)
    get_bucket = conn.get_bucket(bucketname)
    #set bucket acl
    get_bucket.set_acl('authenticated-read')
    for bucket in conn.get_all_buckets():
        print "{name}\t{created}".format(
        name=bucket.name,
        created=bucket.creation_date,
    )
    acp = get_bucket.get_acl()
    for grant in acp.acl.grants:
        print(grant.display_name, grant.permission)


def main():
    #config
    hostname = "Your_ip"
    port = "ssh_port"
    username = "your_username"
    password = "your_passw0rd"
    uid = "your_ceph_username" #Ceph username
    endpoint = "endpoint"
    bucketname = "your_bucket"

    #create a user
    user_create_command = "radosgw-admin user create --uid="+ uid +" --display-name="+ uid
    create_user(hostname, port, username, password, user_create_command)

    #get ak & sk
    get_access_key = "radosgw-admin user info --uid=" + uid + "|grep access_key|awk -F'\"' {'print $4'} "
    get_secret_key = "radosgw-admin user info --uid=" + uid + "|grep secret_key|awk -F'\"' {'print $4'} "
    ak = s3_access_key(hostname, port, username, password, get_access_key)
    sk = s3_secret_key(hostname, port, username, password, get_secret_key)

    #create a bucket
    create_bucket(endpoint, ak, sk, bucketname)

if __name__ == "__main__":
    main()