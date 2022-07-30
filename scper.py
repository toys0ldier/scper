import os, argparse, sys, re, pathlib, getpass, platform, json, hashlib, uuid
from paramiko import SSHClient, AutoAddPolicy
from dateutil.parser import parse
from scp import SCPClient, SCPException
from datetime import datetime
import pandas as pd

lineRe = re.compile(r'^[a-z-]{10}\s{1,4}[0-9]{1,200}\s{1,4}[a-zA-Z]{1,8}\s{1,4}[a-zA-Z]{1,8}\s{1,44}(?P<size>[0-9]{1,36})\s(?P<date>[a-zA-Z]{3,4}\s{1,3}[0-9]{1,2}\s{1,3}[0-9:]{2,5})\s(?P<filename>.*)$')

def parseArgs():
    ap = argparse.ArgumentParser(
        description='uploads and downloads files via scp from remote host(s)',
        conflict_handler='resolve',
        epilog='v%s, created by toys0ldier (2022) https://github.com/toys0ldier' % verNum
    )
    ap.add_argument(
        '-f',
        required=False,
        action='store_true',
        help='force overwrite even if file already exists'
    )
    ap.add_argument(
        '-d',
        nargs='?',
        required=False,
        help='path to file or directory to download',
        metavar=('path')
    )
    ap.add_argument(
        '-u',
        nargs=2,
        required=False,
        help='path to file or directory to upload & upload location',
        metavar=('[path]')
    )
    ap.add_argument(
        '-e',
        nargs='+',
        required=False,
        help='execute command on remote host (enclose command in "quotes")',
        metavar=('cmd')
    )
    ap.add_argument(
        '-v',
        required=False,
        action='store_true',
        help='view or set the default server parameters',
    )
    ap.add_argument(
        '-r',
        required=False,
        action='store_true',
        help='remove one or more server parameters',
    )
    ap.add_argument(
        '--PATH',
        nargs='?',
        required=False,
        help='specify or change default save location',
        metavar=('path')
    )
    ap.add_argument(
        '--RHOST',
        nargs='?',
        required=False,
        help='add remote host (port is optional)',
        metavar=('ipv4:port')
    )
    ap.add_argument(
        '--USER',
        nargs='?',
        required=False,
        help='add username for remote host',
        metavar=('uname')
    )
    ap.add_argument(
        '--PASS',
        nargs='?',
        required=False,
        help='add password for remote host (optional)',
        metavar=('pwd')
    )
    ap.add_argument(
        '--TOKEN',
        nargs='?',
        required=False,
        help='add RSA token for remote host (optional)',
        metavar=('path')
    )
    return ap.parse_args(sys.argv[1:])

class Config:

    def initialize(verNum):
        
        def getUserHash():
            SHA1 = hashlib.sha1()
            SHA1.update(slackName.encode('utf-8'))
            SHA1.update(getpass.getuser().encode('utf-8'))
            SHA1.update(platform.platform().encode('utf-8'))
            return SHA1.hexdigest()
        
        if args.RHOST and args.USER and args.PASS or args.TOKEN:
            sigFile = os.path.join(pathlib.Path(__file__).parent.resolve(), '.user_info')
            if not os.path.exists(sigFile):
                print('[!] Found no user info file, please register your account for gamification purposes!')
                slackName = input('Enter Slack name: ')
                defaultSavePath = input('Enter default save directory: ')
                botUuid = getUserHash()
                with open(sigFile, 'w') as f:
                    userData = {
                            'slackName': slackName,
                            'computername': getpass.getuser(),
                            'platform': platform.platform(),
                            'botUuid': botUuid,
                            'entry_date': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                            'version_num': verNum,
                            'default_save_path': defaultSavePath,
                            'server_configs': [{
                                'RHOST': args.RHOST.strip(),
                                'USER': args.USER.strip(),
                                'PASS': args.PASS.strip() if args.PASS else None,
                                'TOKEN': args.TOKEN.strip() if args.TOKEN else None,
                                'PRIMARY': True
                            }]
                    }
                    f.write(json.dumps(userData, indent=4))
            else:
                userData = json.loads(open(sigFile, 'r').read())
                for config in userData['server_configs']:
                    config['PRIMARY'] = False
                userData['server_configs'].append({
                    'RHOST': args.RHOST.strip(),
                    'USER': args.USER.strip(),
                    'PASS': args.PASS.strip() if args.PASS else None,
                    'TOKEN': args.TOKEN.strip() if args.TOKEN else None,
                    'PRIMARY': True
                })
                with open(sigFile, 'w') as f:
                    f.write(json.dumps(userData, indent=4))
            print('\nSuccessfully created configuration file!')
            df = pd.DataFrame(userData['server_configs'])
            print(df)
            sys.exit(1)
        else:
            print('[!] Error: must supply RHOST, USER, and either PASS or TOKEN!')
            sys.exit(1)

    def view():
        sigFile = os.path.join(pathlib.Path(__file__).parent.resolve(), '.user_info')
        if not os.path.exists(sigFile):
            print('[!] Error: re-run with RHOST, USER, and PASS of TOKEN flags to create config!')
            sys.exit(1)
        else:
            userData = json.loads(open(sigFile, 'r').read())
            df = pd.DataFrame(userData['server_configs'])
            print(df)
            if args.v:
                indexNum = input('[+] Enter the index number of desired primary server (ENTER to cancel): ')
                if indexNum:
                    for i, config in enumerate(userData['server_configs']):
                        if i == int(indexNum):
                            config['PRIMARY'] = True
                        else:
                            config['PRIMARY'] = False
                    with open(sigFile, 'w') as f:
                        f.write(json.dumps(userData, indent=4))
                    SSH_HOST = [s['RHOST'] for s in userData['server_configs'] if(s['PRIMARY'])][0]
                    print('\n[!] Set %s as default server!' % SSH_HOST)
            else:
                indexNum = input('[+] Enter the index number server to delete (ENTER to cancel): ')
                if indexNum:
                    userData['server_configs'].pop(int(indexNum))
                    if not any(p['PRIMARY'] for p in userData['server_configs']):
                        for i, config in enumerate(userData['server_configs']):
                            if i == 0:
                                config['PRIMARY'] = True
                            else:
                                config['PRIMARY'] = False
                    with open(sigFile, 'w') as f:
                        f.write(json.dumps(userData, indent=4))
                    SSH_HOST = [s['RHOST'] for s in userData['server_configs'] if(s['PRIMARY'])][0]
                    print('\n[!] Set %s as default server!' % SSH_HOST)
            sys.exit(1)
        
    def update():
        if args.PATH and args.PATH != ' ':
            sigFile = os.path.join(pathlib.Path(__file__).parent.resolve(), '.user_info')
            userData = json.loads(open(sigFile, 'r').read())
            userData['default_save_path'] = args.PATH.strip()
            print('[+] Set default save path: %s' % args.PATH)
            with open(sigFile, 'w') as f:
                f.write(json.dumps(userData, indent=4))
            sys.exit(1)
        else:
            print('[!] Error: no path supplied for default save location!')
            sys.exit(1)
        
    def retrieve():
        sigFile = os.path.join(pathlib.Path(__file__).parent.resolve(), '.user_info')
        if not os.path.exists(sigFile):
            print('[!] Error: re-run with RHOST, USER, and PASS of TOKEN flags to create config!')
            sys.exit(1)
        else:
            return json.loads(open(sigFile, 'r').read()) 

def execCommand():
    stdin, stdout, stderr = client.exec_command(' '.join(args.e))
    lines = stdout.read().splitlines()
    for line in lines:
        print(line.decode('utf-8'))

def uploadUserStats(userData, numFiles, numBytes):
    statsFile = os.path.join(pathlib.Path(__file__).parent.resolve(), str(uuid.uuid4()))
    with open(statsFile, 'w') as f:
        userData = {
            'slackName': userData['slackName'],
            'botUuid': userData['botUuid'],
            'last_submission_date': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            'files_submitted': numFiles,
            'bytes_submitted': numBytes
        }
        f.write(json.dumps(userData))
    print('[-] Updating user statistics and cleaning up temporary files...')
    scp.put(statsFile, recursive=False, remote_path='/var/log/gamify/%s' % str(uuid.uuid4()))
    os.remove(statsFile)
                
def formatSize(size):
    if size < 1048576:
        return '{:,}'.format(round(size / 1024, 2)) + ' KB'
    elif size > 1048576 and size < 1073741824:
        return '{:,}'.format(round(size / 1048576, 2)) + ' MB'
    else:
        return '{:,}'.format(round(size / 1073741824, 2)) + ' GB'

def progress(fileName, fileSize, bytesSent):
    printWidth = (os.get_terminal_size().columns - 25)
    printName = fileName.decode('utf-8')
    if len(printName) < printWidth:
        for _ in range(0, (printWidth - len(printName))):
            printName += ' '
    elif len(printName) > printWidth:
        printName = '...' + fileName.decode('utf-8')[-(printWidth - 3):]
    else:
        pass
    sys.stdout.write("%s [ Progress: %.2f%% ]   \r" % (printName, float(bytesSent) / float(fileSize) * 100))
        
def createClient(userData):
    SSH_HOST = [s['RHOST'] for s in userData['server_configs'] if(s['PRIMARY'])][0]
    SSH_USERNAME = [u['USER'] for u in userData['server_configs'] if(u['PRIMARY'])][0]
    SSH_PASSWORD = [p['PASS'] for p in userData['server_configs'] if(p['PRIMARY'])][0]
    if not SSH_PASSWORD:
        SSH_TOKEN = [t['TOKEN'] for t in userData['server_configs'] if(t['PRIMARY'])][0]
    client = SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(AutoAddPolicy())
    if SSH_PASSWORD:
        client.connect(hostname=SSH_HOST, username=SSH_USERNAME, password=SSH_PASSWORD)
    else:
        client.connect(hostname=SSH_HOST, username=SSH_USERNAME, key_filename=SSH_TOKEN)
    scp = SCPClient(client.get_transport(), progress=progress)
    return client, scp

def checkPathType(dlPath):
    stdin, stdout, stderr = client.exec_command('%s %s' % ('ls -alt', dlPath))
    lines = stdout.read().splitlines()
    subEntries = []
    for line in lines:
        data = re.search(lineRe, line.decode('utf-8'))
        if data:
            data = data.groupdict()
            data['date'] = parse(data['date'])
            data['size'] = formatSize(int(data['size']))
            if 'classified_danger_folder' in data['filename']:
                print('[!] Danger Will Robinson! Detected potential classified data in requested dowload!')
                print('[!] Quitting...')
            elif data['filename'].endswith(('.', '/')):
                pass
            else:
                subEntries.append(data)
    return subEntries
    
def autoDownload(userData, fileEntry):
    try:
        print('[+] Downloading: %s' % fileEntry['filename'])
        fileStruct = os.path.join(userData['default_save_path'], os.path.split(fileEntry['filename'])[0].lstrip('/root/data/'))
        if not os.path.exists(fileStruct):
            os.makedirs(fileStruct)
        filePath = os.path.join(fileStruct, os.path.split(fileEntry['filename'])[1])
        if os.path.exists(filePath) and not args.f:
            print('[!] File %s already exists at destination.' % fileEntry['filename'])
            print('[!] Add -f flag to force overwrite!')
            sys.exit(1)
        scp.get(fileEntry['filename'], local_path=fileStruct, preserve_times=True)
        print('    Successfully downloaded file %s. Total download size: %s.' % (fileEntry['filename'], fileEntry['size']))
    except SCPException as err:
        if 'No such file or directory' in str(err):
            print('[!] Could not find file or directory matching input path!')
            print('[!] Check the input path and try again. File may have been renamed or removed!')
            sys.exit(1)
        elif 'not a regular file' in str(err):
            return checkPathType(fileEntry)
        else:
            print(err)
    return None

def autoUpload(filePath, remotePath):
    try:
        if os.path.isdir(filePath):
            print('[+] Uploading folder %s to %s (recursive upload).' % (filePath, remotePath))
            scp.put(filePath, recursive=True, remote_path=remotePath)
            print('    Successfully uploaded folder %s and its contents.' % filePath)
            numFiles = 0
            numBytes = 0
            for entry in os.scandir(filePath):
                if entry.is_file():
                    numFiles += 1
                    numBytes += entry.stat().st_size
            return numFiles, numBytes
        else:
            print('[+] Uploading file %s to %s.' % (filePath, remotePath))
            scp.put(filePath, recursive=False, remote_path=remotePath)
            print('    Successfully uploaded file %s.' % filePath)
            return 1, os.stat(filePath).st_size
    except SCPException as err:
        if 'Not a directory' in str(err):
            client.exec_command('%s %s' % ('mkdir', remotePath))
            autoUpload(filePath, remotePath)
        else:
            print(err)
        
def main():
    global client, scp, args
    args = parseArgs()
    if args.RHOST:
        userData = Config.initialize(verNum)
    elif args.v or args.r:
        Config.view()
    elif args.PATH:
        Config.update()
    else:
        userData = Config.retrieve()
    client, scp = createClient(userData)
    if args.e:
        execCommand()
    if args.d:
        fileEntries = checkPathType(args.d)
        orphanFiles = []
        if len(fileEntries) >= 1:
            for fileEntry in fileEntries:
                fileEntry['filename'] = os.path.join(args.d, fileEntry['filename'])
                orphanFiles.append(autoDownload(userData, fileEntry))
        else:
            orphanFiles.append(autoDownload(userData, fileEntries[0]))
        # while orphanFiles:
        #     for i, orphanFile in enumerate(orphanFiles):
        #         autoDownload(userData, orphanFile)
        #         orphanFiles.pop(i)
    elif args.u:
        numFiles, numBytes = autoUpload(args.u[0], args.u[1])
        uploadUserStats(userData, numFiles, numBytes)
    client.close()
    
if __name__ == '__main__':
    
    verNum = '1.0.1b'
    main()