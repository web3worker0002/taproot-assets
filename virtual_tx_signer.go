package taprootassets

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapscript"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许跨域
	},
}

// LndRpcVirtualTxSigner is an implementation of the tapscript.Signer
// interface backed by an active lnd node.
type LndRpcVirtualTxSigner struct {
	lnd                 *lndclient.LndServices
	Wsservice, Wsclient *http.Server
	Wscon               *websocket.Conn
	SignRequestMap      map[string][]byte
	SignResponseMap     map[string][][]byte
}

type SignRequest struct {
	Id   string
	Data SignDataRequest
}

func (Sr SignRequest) Serialize() []byte {

	data, err := json.Marshal(Sr)
	if err != nil {
		return nil
	}
	return data
}

func (Sr SignRequest) FromBytes(data []byte) *SignRequest {

	var signRequest *SignRequest
	err := json.Unmarshal(data, &signRequest)
	if err != nil {
		return nil
	}
	return signRequest
}

type SignDataRequest struct {
	SignDesc *lndclient.SignDescriptor
	Tx       *wire.MsgTx
}

type SignOutStruct struct {
	Id         string
	Signatures [][]byte
}

func (Sos SignOutStruct) Serialize() []byte {

	data, err := json.Marshal(Sos)
	if err != nil {
		return nil
	}
	return data

}

func (Sos SignOutStruct) FromBytes(data []byte) SignOutStruct {

	var signOutStruct *SignOutStruct
	err := json.Unmarshal(data, &signOutStruct)
	if err != nil {
		return SignOutStruct{}
	}

	Sos.Id = signOutStruct.Id
	Sos.Signatures = signOutStruct.Signatures
	return Sos

}

// NewLndRpcVirtualTxSigner returns a new tx signer instance backed by the
// passed connection to a remote lnd node.
func NewLndRpcVirtualTxSigner(lnd *lndclient.LndServices) *LndRpcVirtualTxSigner {

	LSigner := &LndRpcVirtualTxSigner{
		lnd: lnd,
	}

	go LSigner.StartWsService()
	return LSigner
}

func (l *LndRpcVirtualTxSigner) Handler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil) // 升级为WebSocket连接
	if err != nil {
		return
	}
	defer conn.Close()

	l.Wscon = conn
	for {

		//if conn failed retry
		if l.Wscon == nil {
			conn, err := upgrader.Upgrade(w, r, nil) // 升级为WebSocket连接
			if err != nil {
				return
			}
			defer conn.Close()
			l.Wscon = conn
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			return // 断开连接
		}

		signOut := SignOutStruct{}.FromBytes(message)

		if _, ok := l.SignRequestMap[signOut.Id]; ok {

			l.SignResponseMap[signOut.Id] = signOut.Signatures
			//remove sign id
			delete(l.SignRequestMap, signOut.Id)

			//notify the main call

		} else {
			fmt.Println("sign id not found")
			continue
		}

		// if string(message) == "sign" {

		// 	// sign virtual tx
		// 	// signDesc := &lndclient.SignDescriptor{}
		// 	// tx := &wire.MsgTx{}
		// 	// prevOut := &wire.TxOut{}
		// 	// virtualTxSig, err := l.SignVirtualTx(signDesc, tx, prevOut)
		// 	// if err != nil {
		// 	// 	return
		// 	// }
		// 	// err = conn.WriteMessage(messageType, virtualTxSig.Serialize()) // 回复客户端
		// 	// if err != nil {
		// 	// 	return
		// 	// }
		// }
	}
}

func (l *LndRpcVirtualTxSigner) StartWsService() {

	http.HandleFunc("/ws", l.Handler)
	http.ListenAndServe(":55555", nil)
}

// SignVirtualTx generates a signature according to the passed signing
// descriptor and virtual TX.
func (l *LndRpcVirtualTxSigner) SignVirtualTx(signDesc *lndclient.SignDescriptor,
	tx *wire.MsgTx, prevOut *wire.TxOut) (*schnorr.Signature, error) {

	// sigs, err := l.lnd.Signer.SignOutputRaw(
	// 	context.Background(), tx, []*lndclient.SignDescriptor{     },
	// 	[]*wire.TxOut{prevOut},
	// )
	// if err != nil {
	// 	return nil, err
	// }

	//create random uuid
	id := uuid.New().String()
	request := SignRequest{
		Id: id,
		Data: SignDataRequest{
			SignDesc: signDesc,
			Tx:       tx,
		},
	}

	err := l.Wscon.WriteMessage(1, request.Serialize())
	if err != nil {
		return nil, err
	}
	l.SignRequestMap[id] = request.Serialize()

	//wait for the signature
	for {

		if _, ok := l.SignResponseMap[id]; ok {
			log.Println("signature received")
			break
		} else {
			time.Sleep(1 * time.Second)
		}

		//todo, need to improve the logic
	}

	// wait for the signature

	// Our signer should only ever produce one signature or fail before this
	// point, so accessing the signature directly is safe.
	// virtualTxSig, err := schnorr.ParseSignature(sigs[0])
	virtualTxSig, err := schnorr.ParseSignature(l.SignResponseMap[id][0])
	request.Serialize()
	if err != nil {
		return nil, err
	}

	return virtualTxSig, nil
}

// Compile time assertions to ensure LndRpcVirtualTxSigner meets the
// tapscript.Signer and asset.GenesisSigner interfaces.
var _ tapscript.Signer = (*LndRpcVirtualTxSigner)(nil)

var _ asset.GenesisSigner = (*LndRpcVirtualTxSigner)(nil)
