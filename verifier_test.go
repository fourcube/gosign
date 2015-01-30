package main

import (
	"encoding/hex"
	"reflect"
	"testing"
)

var testHash []byte
var testSigned []byte

func init() {
	testHash, _ = hex.DecodeString("e79b8ad22b34a54be999f4eadde2ee895c208d4b3d83f1954b61255d2556a8b73773c0dc0210aa044ffcca6834839460959cbc9f73d3079262fc8bc935d46262")
  testSigned, _ = hex.DecodeString("5b11a7fae8b199cbbd8c496fb4f65c0340321572c449df174bad2f663831b9743eba3e2dcc9668a309ac3fd37ae09dd821a5d133b07ae1099fc8d5d0e2eebcef31236869dfbc323285f0f51d47715991a1d4f7027fb6219e58f819c375719fe8a91c813dc29e96ff4e2275951262fc0955bd016db0a8416dd079ee6ee7ca2f2cec34a4ee0d65c60acc622416c11eca5f5abb4f4dbd5bb72fb893ead3a1e8b426a25376ac1634c06605df2e1f0d1fe3f48431e70e9d786ab3633d7470f62edf103580a2141a5bdfd7b3c0537157c0cb57c965cc6c3f1dfc81076858d14c756b40b26baa17cf203194a50b07b4fbe9031cf28079437ae49f5901f19e9c638cab23")
}

func TestVerifySHA512(t *testing.T) {
	key := loadPublicKey("test.pub")
	data := GetHash("test.bin")

	valid, err := VerifySHA512(key, data, testSigned)

	if !valid || err != nil {
		t.Errorf("Signature verification failed %v", err)
	}
}

func TestSignSHA512(t *testing.T) {
  key := loadPrivateKey("test.key")
  signed := SignSHA512(key, testHash)

  if !reflect.DeepEqual(testSigned, signed) {
    t.Errorf("Signing failed.")
  }
}


func TestGetHash(t *testing.T) {
	if !reflect.DeepEqual(GetHash("test.bin"), testHash) {
		t.Errorf("Hash failed.")
	}
}

func TestLoadPublicKey(t *testing.T) {
  key := loadPublicKey("test.pub")

  if key == nil {
    t.Errorf("key is nil")
  }
}

func TestLoadPublicKeyFileDoesntExist(t *testing.T) {
  key := loadPublicKey("test.pub.noexists")

  if key != nil {
    t.Errorf("key should be nil")
  }
}

func TestLoadPublicKeyNotAPublicKey(t *testing.T) {
  key := loadPublicKey("test.key")

  if key != nil {
    t.Errorf("key should be nil")
  }
}

func TestLoadPublicKeyNotPEMEncoded(t *testing.T) {
  key := loadPublicKey("test.bin")

  if key != nil {
    t.Errorf("key should be nil")
  }
}

func TestLoadPrivateKey(t *testing.T) {
	key := loadPrivateKey("test.key")

	if key == nil {
		t.Errorf("key is nil")
	}
}

func TestLoadPrivateKeyFileDoesntExist(t *testing.T) {
  key := loadPrivateKey("test.key.noexists")

  if key != nil {
    t.Errorf("key should be nil")
  }
}

func TestLoadPrivateKeyNotAPrivateKey(t *testing.T) {
  key := loadPrivateKey("test.pub")

  if key != nil {
    t.Errorf("key should be nil")
  }
}

func TestLoadPrivateKeyNotPEMEncoded(t *testing.T) {
  key := loadPrivateKey("test.bin")

  if key != nil {
    t.Errorf("key should be nil")
  }
}
