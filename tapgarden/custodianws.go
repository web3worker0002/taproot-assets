package tapgarden

import (
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许跨域
	},
}

type CustodianWs struct {
	Wscon *websocket.Conn
	//create a channel to receive proof event
	CreateEvent chan string
}

func (l *CustodianWs) Handler(w http.ResponseWriter, r *http.Request) {
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

		for x := range l.CreateEvent {

			log.Info("CustodianWs: get event and transfer to client side")
			if x == "create" {
				err := conn.WriteMessage(websocket.TextMessage, []byte("create"))
				if err != nil {
					log.Error("CustodianWs: write message failed:", err)
					continue
				}
			}
		}

		// send message to client side

		// err := conn.WriteMessage(websocket.TextMessage, []byte("hello"))

		// _, message, err := conn.ReadMessage()
		// if err != nil {
		// 	return // 断开连接
		// }

		// signOut := SignOutStruct{}.FromBytes(message)

		// if _, ok := l.SignRequestMap[signOut.Id]; ok {

		// 	l.SignResponseMap[signOut.Id] = signOut.Signatures
		// 	//remove sign id
		// 	delete(l.SignRequestMap, signOut.Id)

		// 	//notify the main call

		// } else {
		// 	fmt.Println("sign id not found")
		// 	continue
		// }
	}
}

func (l *CustodianWs) StartWsService() {

	http.HandleFunc("/ws", l.Handler)
	http.ListenAndServe(":55555", nil)
}
