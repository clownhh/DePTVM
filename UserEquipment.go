package main

import (
	"NPTM/proto"
	"NPTM/util"
	"bufio"
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"

	"go.dedis.ch/kyber/v4/suites"
)

//go run UserEquipment.go
//part code of NE

//define part
type UserEquipment struct {
	//net config
	AccessPointAddr *net.UDPAddr
	Socket          *net.UDPConn
	Status          int
	//crypto variables
	Suite            suites.Suite
	PrivateKey       kyber.Scalar
	PublicKey        kyber.Point
	OnetimePseudoNym kyber.Point
	G                kyber.Point
}

//status

// configuration
const UE_CONFIGURATION = 0

// connected with OA
const UE_CONNECTED = 1

//function part
var userEquipment *UserEquipment

func Handle_UE(buf []byte, addr *net.UDPAddr, tmpUserEquipment *UserEquipment, n int) {
	//decode the event
	userEquipment = tmpUserEquipment
	event := &proto.Event{}
	err := gob.NewDecoder(bytes.NewReader(buf[:n])).Decode(event)
	util.CheckErr(err)

	switch event.EventType {
	case proto.UE_REGISTER_CONFIRMATION:
		handleRegisterConfirmation(userEquipment)
		break
	case proto.SYNC_REPMAP:
		handleSyncRepUE(event.Params, userEquipment)
		break
	default:
		fmt.Println("[UE] Unrecognized request!")
		break
	}
}

//init
func initUE(APAddr string) {
	//load AP's ip and port
	AccessPointAddr, err := net.ResolveUDPAddr("udp", APAddr)
	util.CheckErr(err)
	//initlize suite
	suite := edwards25519.NewBlakeSHA256Ed25519()  // Use the edwards25519-curve
	a := suite.Scalar().Pick(suite.RandomStream()) // Alice's private key
	A := suite.Point().Mul(a, nil)
	userEquipment = &UserEquipment{AccessPointAddr, nil, UE_CONFIGURATION, suite, a, A, suite.Point(), nil}
	fmt.Println("[UE] Parameter initialization is complete.")
	fmt.Println("[UE] My public key is ", userEquipment.PublicKey)
}

//register
func registerUE() {
	// set the parameters to register
	bytePublicKey, _ := userEquipment.PublicKey.MarshalBinary()
	params := map[string]interface{}{
		"public_key": bytePublicKey,
	}
	event := &proto.Event{proto.UE_REGISTER_APSIDE, params}
	util.SendToAccessPoint(userEquipment.Socket, util.Encode(event))
}

// print out register success info
func handleRegisterConfirmation(userEquipment *UserEquipment) {
	//print out the register success info
	fmt.Println("[UE] Register success !")
	userEquipment.Status = UE_CONNECTED

}

//get UE's one-time pseudonym and g
func handleSyncRepUE(params map[string]interface{}, userEquipment *UserEquipment) {
	//set one-time pseudonym and g
	g := userEquipment.Suite.Point()
	// deserialize g and calculate nym
	g.UnmarshalBinary(params["g"].([]byte))
	nym := userEquipment.Suite.Point().Mul(userEquipment.PrivateKey, g)
	//set UE'S parameters
	userEquipment.G = g
	userEquipment.OnetimePseudoNym = nym

	//print out the UE's nym
	fmt.Println("[UE] One-Time pseudonym for this round is :", userEquipment.OnetimePseudoNym)
}

func startUEListener() {
	fmt.Println("[UE] UserEquiment Listener started...")
	buf := make([]byte, 4096)
	for {
		n, addr, err := userEquipment.Socket.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}
		go Handle_UE(buf, addr, userEquipment, n)
	}
}

//main function
func main() {
	//get AP's address

	fmt.Println("[UE] User equiment started!")
	fmt.Print("[UE] Please enter the IP address of the access point: ")
	reader := bufio.NewReader(os.Stdin)
	ipdata, _, err := reader.ReadLine()
	if err == nil {
		fmt.Println("[UE] Enter success!")
	}
	APAddr := string(ipdata)

	//initial params and network configurations
	initUE(APAddr)

	conn, err := net.DialUDP("udp", nil, userEquipment.AccessPointAddr)
	util.CheckErr(err)

	//set socket
	userEquipment.Socket = conn
	//start listener
	go startUEListener()
	time.Sleep(1.0 * time.Second)

	registerUE()
	fmt.Println("[UE] Wait for register confirmation.")
	for userEquipment.Status != UE_CONNECTED {
		//wait for UE register success
	}

	// read command and process
	fmt.Println("[UE] Enter your command.")

Loop:
	for {
		fmt.Print("cmd >> ")
		data, _, _ := reader.ReadLine()
		command := string(data)
		commands := strings.Split(command, " ")
		switch commands[0] {
		case "exit":
			break Loop
		default:
			fmt.Println("[UE] Hello!")
		}

	}

	conn.Close()
	fmt.Println("[UE] Exit system...")
}
