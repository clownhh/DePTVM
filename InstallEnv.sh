#!/bin/bash
echo "==========Start to download Golang!=========="
wget https://studygolang.com/dl/golang/go1.20.4.linux-amd64.tar.gz -O go.tar.gz
echo "==============Extracting Golang!============="
tar -xzvf go.tar.gz
echo "==============Install Golang!================"
sudo mv go /usr/local/
rm -rf go.tar.gz
echo "==============Setup Environment!============="
echo "export PATH=\$PATH:/usr/local/go/bin" | sudo tee -a /etc/profile
echo "===============Load env!====================="
source /etc/profile
echo "======setup golang and install dependence===="
go version
go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn
go env
go mod init NPTM
go get github.com/shopspring/decimal
go get go.dedis.ch/kyber/v4
go get go.dedis.ch/kyber/v4/group/edwards25519
go get go.dedis.ch/kyber/v4/suites
go get go.dedis.ch/kyber/v4/util/random
go get go.dedis.ch/protobuf
go get github.com/izqui/helpers
go get github.com/xsleonard/go-merkle
go get go.dedis.ch/kyber/v4/proof
go get go.dedis.ch/kyber/v4/shuffle
go get go.dedis.ch/kyber/v4/sign/anon
echo "=============Install terminator=============="
sudo apt install terminator -y
reboot

