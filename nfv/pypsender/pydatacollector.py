__author__ = 'zhizhong pan'


import subprocess
import os
import time

def collector_data():
    packet_size_list = [64, 128, 256, 512, 1024]
    firewall_rules_min = 0
    firewall_rules_max = 2200
    step = 200

    server_id = os.fork()
    if server_id == 0:
        print '++++++++++++   set server!    ++++++++++++++'
        subprocess.call(['ssh', 'hongdal@130.127.133.17', 'sudo iperf -s -p 5001'])
    else:
        time.sleep(2)
        print '++++++++++++   destroy old click0  !+++++++++++++'
        subprocess.call(['xl', 'destroy', 'click0'])
        click_id = os.fork()
        if click_id == 0: 
            print '++++++++++++   create click0   !++++++++++++++'
            subprocess.call(['xl', 'create', '/local/nfv-exp/config.xen'])
            subprocess.call(['cosmos', 'start', 'click0', '/local/nfv-exp/firewall00.click'])
            subprocess.call(['xl', 'console', 'click0', '>', 'raw.data'])
        else:
            time.sleep(2)
            print '+++++++++++++   send rules!   +++++++++++++'
            subprocess.call(['/local/work/clickos/nfv/pypsender/batchsender.sh', '10'])
            print '+++++++++++++   set client!   +++++++++++++'
            subprocess.call(['ssh', 'hongdal@130.127.133.32', 'sudo iperf -c server -p 5001'])
            print '+++++++++++++   destroy click0!   +++++++++++++'
            subprocess.call(['xl', 'destroy', 'click0'])


if __name__ == '__main__':
    collector_data()
