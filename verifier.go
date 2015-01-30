package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"encoding/hex"
	"crypto"
	"io"
	"fmt"
	"io/ioutil"
	"log"
	"flag"
	"os"
)

var (
	privateKey = flag.String("privateKey", "", "Private key for signatures - no password")
	file = flag.String("file", "", "File to sign")
	sign = flag.Bool("sign", true, "Signature mode")
	hash = flag.Bool("hash", false, "SHA512 hash mode")
)

func main() {
	flag.Parse()

	if *sign {
		k := loadPrivateKey(*privateKey)
		if k == nil {
			log.Printf("Couldn't load %v", *privateKey)
			return
		}

		h := GetHash(*file)
		if h == nil {
			log.Printf("Couldn't create hash for %v", *file)
		}

		signature := SignSHA512(k, h)
		if signature == nil {
			log.Printf("Couldn't create signatur for %v using %v", *file, *privateKey)
		}

		fmt.Printf("%v\n", hex.EncodeToString(signature))
	} else if *hash {

	} else {
		log.Printf("Error: Either -sign or -hash required.")
		flag.PrintDefaults()
	}
}

// VerifySHA512 verifies data's signature using the supplied publicKey
func VerifySHA512(publicKey *rsa.PublicKey, data []byte, signature []byte) (valid bool, err error) {
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, data, signature)

	if err == nil {
		valid = true
	}

	return
}

// SignSHA512 signs hash with the supplied private key
func SignSHA512(privateKey *rsa.PrivateKey, hash []byte) (signed []byte) {
	signed, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hash)

	if err != nil {
		log.Printf("Signing failed %v", err)
		return
	}
	return
}

// GetHash calculates the hash of the file at path
func GetHash(path string) (h []byte) {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}

	hash := sha512.New()
	io.Copy(hash, file)
	return hash.Sum(nil)
}

func loadPublicKey(path string) (pub *rsa.PublicKey) {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("Failed to open %v", path)
		return nil
	}

	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Printf("Failed to read %v", path)
		return nil
	}

	block, _ := pem.Decode(data)
	if block == nil {
		log.Printf("Failed to decode %v", path)
		return nil
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Printf("Failed to parse public key %v", path)
		return nil
	}

	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		log.Printf("Type assertion failed %v is not a public key", path)
		return nil
	}
	return
}

func loadPrivateKey(path string) (pk *rsa.PrivateKey) {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("Failed to open %v", path)
		return nil
	}

	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Printf("Failed to read %v", path)
		return nil
	}

	block, _ := pem.Decode(data)
	if block == nil {
		log.Printf("Failed to decode %v", path)
		return nil
	}

	pk, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("Failed to parse private key %v", path)
		return nil
	}

	return
}
