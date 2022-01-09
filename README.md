This is a rebuilt version of [zhanglikernel/CRYPTOREX: Large-scale Analysis of Cryptographic Misuse in IoT Devices (github.com)](https://github.com/zhanglikernel/CRYPTOREX) to make it can be easily used by other researcher

# Environment

- linux with **root** previlege, or binwalk won't work
- Python 3.9
- angr
- buildroot
- IDA Pro v6.4 Linux

# Installation

## Install angr

Download `angr`

```
apt-get install python3-dev libffi-dev build-essential virtualenvwrapper
whereis virtualenvwrapper.sh
source /usr/share/virtualenvwrapper/virtualenvwrapper.sh
mkvirtualenv --python=$(which python3) angr && pip install angr
```

Enable virtual environment

```
source /usr/share/virtualenvwrapper/virtualenvwrapper.sh
```

`workon`  to check available environment 

```
root@kali:~# workon
angr
```

Enter `angr` virtual environment

```
root@kali:~# workon angr
(angr) root@kali:~#
```

Exit virtual environment after the execution finished

```
(angr) root@kali:~# deactivate
root@kali:~#
```

**Angr ocumentation Node**: Do not attempt to solve any angr problems outside of the virtual environment

## Install buildroot

## Install IDA pro

```
链接: https://pan.baidu.com/s/1bdBhVTBYMk0lNIOtCxIjPw 提取码: w28g
```

## Install python requirement

```
pip install rarfile
pip install python-magic
pip install binwalk
```

# Configuration

Config your own tool path in config.py

```
home_path = "$HOME/Downloads"

buildroot_path = ""

output_path = home_path + "/CRYPTOREX/rex/rexProject"

ida_path = home_path + "/IDA_Pro_v6.4_Linux"

script_path = home_path + "/CRYPTOREX/idascript/bin2iridc.idc"

misuseprofile_path = home_path + "/CRYPTOREX/rex/misuseprofile"

excfunction_path = home_path + "/CRYPTOREX/rex/execfunction"
```

# Usage

这里把命令行改掉了, 不用输入那么多中间命令. 所有文件默认存在当前工作目录的 ./rexProject 目录下

直接使用

```
(anrg)root@kali:~# python bin2vex.py -i [要分析的固件] -o [要输出的目录，default =./rexProject] -v [是否保留中间文件，建议选上] 
```

一共会输出4个文件，

第一个是解包后的固件包，存在./rexProject/decompress下

第二个是提取后的文件，存在./rexProject/extracted下

第三个是提取的IR文件，存在./rexProject/ir下

若勾选-v, 前三个中间文件在执行结束后将保留，否则执行结束后删除

第四个是report，存在./rexProject/report