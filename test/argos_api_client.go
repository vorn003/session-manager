
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	argosapi "sshmenu/api"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: argos_api_client <api-url>")
	}
	apiURL := os.Args[1]
	result, err := argosapi.Run(context.Background(), apiURL)
	if err != nil {
		log.Fatal(err)
	}

	pretty, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(pretty))
}