# 加密壳

### 开发环境：
Win10 VisualStudio2010 Win32SDK 多字节集编码 x86

### 介绍：
对32位可执行程序进行加密保护，被保护程序在文件状态时，所有二进制数据都装在外壳程序的新增节中，只有程序运行起来，外壳程序才将受保护程序替换执行。   

### 原理：
1.打包程序：在壳源程序中新增加一个节，这个节用来存放加密后的被保护程序的二进制数据。生成新的exe文件。

2.新生成的exe：这个程序首先把自身最后一个节中的数据抽取出来，进行解密。以挂起方式创建一个自身傀儡进程，获取线程上下文，卸载傀儡进程的内存，在傀儡进程空间分配一块内存(大小为受保护程序的SizeOfImage)，将解密出来的数据写入这个新分配出来的空间。判断一下分配出来的地址和受保护程序的基址是否一致，如果不一致就要修复重定位表，如果受保护程序没有重定位表，程序退出。如果程序继续运行，修正运行环境的基址(新分配内存首地址)和入口地址(受保护程序的OEP)，恢复傀儡线程的主线程。

### 用到知识：
1.PE新增节

2.挂起方式创建进程

3.替换进程内存

4.修复重定位表

### 演示：

#### 打包：
![加密壳-打包](https://ftp.bmp.ovh/imgs/2021/05/ee29240a63c2043c.png)

#### 加密后对比：
![加密壳-对比](https://ftp.bmp.ovh/imgs/2021/05/a0c6afc21e80c991.png)

#### 加密后运行：
![加密壳-运行1](https://ftp.bmp.ovh/imgs/2021/05/57640cf680458288.png)

![加密壳-运行2](https://ftp.bmp.ovh/imgs/2021/05/affa2ecd84a656f0.png)
