# 个人课程项目
实施了区块链定义`block_chain.py`, 并构造了一个简单的小型网络（链接、加密、发送、接收）来测试网络中某些节点离线后的现象，验证了区块链问题中达成共识问题的条件。具体演示请运行 `demonstration.py`。请注意为了同步性，节点初始化阶段用了一个线程锁，本机模拟握手协议需要一定的时间。
## Requirements

Lap top OS
ProductName:	macOS
ProductVersion:	12.6.3
BuildVersion:	21G419,
Darwin Kernel Version 21.6.0

This project requires the following Python3 libraries: 
cffi==1.15.1,
cryptography==40.0.1,
pycparser==2.21

## How to excecute
Simply run `Python3 demonstration.py`.
Please ensure that all python files are in the same folder so that they can import each other.

`demonstration.py` can be regarded as a simulation of a network with 6 nodes tolerating 2 failures. To find out test cases covered, please read comments in `demonstration.py`. You can also manually verify by checking the terminal stdout messages. To sync the print messages, a thread lock is used. Please be patient for the program printing outcomes. There are 6 consensus rounds in total, where the last 2 rounds simulating node failures. 
You could simulate 3 nodes failure by making 3 more nodes and change all node failure tolerance to be 3. Otherwise, the concensus won't decide a block as `f` is set to be 2.







