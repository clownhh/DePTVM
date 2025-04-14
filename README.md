## The implementation of paper: 

[***"Deptvm: Decentralized pseudonym and trust value management for integrated networks"***](https://ieeexplore.ieee.org/abstract/document/10049178)

<img width="910" alt="image" src="https://github.com/eternaldlw/DePTVM/assets/115533295/6177e6f0-8bb2-4562-a41c-6a0dfe6cb26a">

IEEE Transactions on Dependable and Secure Computing 2023

## How to run?

1. Use installEnv.sh to install the necessary Go language packages.
   // sudo ./installEnv.sh
   
   // 如果下载失败，连接不到源：
   
       # 设置代理并关闭校验（推荐）
   
      go env -w GOPROXY=https://goproxy.cn,direct
   
      go env -w GOSUMDB=off
   
2. For each entity(UE/OA/AP/CSP):
  go run _.go

> initial order: CSP>OA>AP>UE


   



