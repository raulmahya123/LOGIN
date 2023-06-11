package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// connect to database mongo db
func DBinstance() *mongo.Client {
	err := godotenv.Load(".env") // mengambil env
	if err != nil {
		log.Fatal("Error loading .env file")
	} // jika error maka akan memunculkan error loading .env file
	MongoDB := os.Getenv("MONGO_URL")                                  // mengambil env mongo db
	client, err := mongo.NewClient(options.Client().ApplyURI(MongoDB)) // membuat client baru
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // membuat context baru
	defer cancel()                                                           // defer cancel
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	} // menghubungkan client dengan context
	fmt.Println("Connected to MongoDB!") // memunculkan connected to mongo db
	return client                        // mengembalikan client
} // mengembalikan client

var Client *mongo.Client = DBinstance() // membuat client baru

func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	var collection *mongo.Collection = client.Database("golangjwt").Collection(collectionName) // membuat collection baru
	return collection                                                                          // mengembalikan collection
}
