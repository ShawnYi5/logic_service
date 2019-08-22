CLW_BOOT_REDIRECT_MBR_UUID = 'clwbootdisk'.ljust(32, '0')
CLW_BOOT_REDIRECT_GPT_UUID = 'clwbootdisk'.ljust(31, '0') + '1'
CLW_BOOT_REDIRECT_GPT_LINUX_UUID = 'clwbootdisk'.ljust(31, '0') + '2'
CLW_BOOT_REDIRECT_GPT_LINUX_INDEX = 9999999
CLW_BOOT_REDIRECT_GPT_LINUX_MOUNT_PATH = '/clw_redirect_boot_gpt_linux'
