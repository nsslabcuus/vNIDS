__author__ = 'zhizhong pan '

import os
work_dir = os.getcwd()

def parser_config(file_name):
    config_file = open(file_name, 'r')
    config_all = {}
    config_instance = []
    instance_flag = 0
    for item in config_file:
        config_list = item.strip().split(",")
        if config_list[0][0] != '#':
            instance_no = config_list[0]
            if instance_no not in config_all:
                config_all[instance_no] = []
            config_all[instance_no].append(config_list[1:])

    return config_all


if __name__ == '__main__':
    config_all = parser_config(work_dir + '/pypsender.cfg')
    print(config_all)
