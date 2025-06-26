package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DBInstance holds the MongoDB client and database instances
type DBInstance struct {
	Client *mongo.Client
	DB     *mongo.Database
}

var DB DBInstance

// ConnectDB establishes connection to MongoDB
func ConnectDB() {
	mongoURI := os.Getenv("MONGODB_URL")
	if mongoURI == "" {
		log.Fatal("MONGODB_URL environment variable not set")
	}

	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		dbName = "jwt_auth_db" // default database name
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Set client options
	clientOptions := options.Client().ApplyURI(mongoURI)

	// Connect to MongoDB
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}

	// Ping the database to verify connection
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
	}

	fmt.Println("Connected to MongoDB!")

	// Set the global DB instance
	DB = DBInstance{
		Client: client,
		DB:     client.Database(dbName),
	}
}

// GetCollection returns a collection from the database
func GetCollection(collectionName string) *mongo.Collection {
	return DB.DB.Collection(collectionName)
}

// DisconnectDB closes the MongoDB connection
func DisconnectDB() {
	if DB.Client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := DB.Client.Disconnect(ctx); err != nil {
			log.Fatal("Failed to disconnect from MongoDB:", err)
		}
		fmt.Println("Disconnected from MongoDB!")
	}
}
