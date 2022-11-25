package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"github.com/auyer/steganography"
	"github.com/pkg/errors"
	"image/jpeg"
	"image/png"
	"log"
	"net/http"
	"os"
)

var encByte = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

// This should be in an env file in production
const MySecret string = "abc&1*~#^2^#s0^=)^^7%b34"

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

// Encrypt method is to encrypt or hide any classified text
func Encrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, encByte)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return Encode(cipherText), nil
}

// Decrypt method is to extract back the encrypted text
func Decrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	cipherText := Decode(text)
	cfb := cipher.NewCFBDecrypter(block, encByte)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

func main() {
	//encode()
	decode("out_file.png")

}

func encode() {
	inFile, err := os.Open("mypic.png") // opening file
	if err != nil {
		log.Fatal(err)
	}
	reader := bufio.NewReader(inFile) // buffer reader
	img, err := png.Decode(reader)    // decoding to golang's image.Image
	if err != nil {
		log.Fatal(err)
	}

	w := new(bytes.Buffer)

	StringToEncrypt := "favour is a goat"
	encText, err := Encrypt(StringToEncrypt, MySecret)

	err = steganography.Encode(w, img, []byte(encText))
	if err != nil {
		log.Printf("Error Encoding file %v", err)
		return
	}
	outFile, _ := os.Create("out_file.png")
	w.WriteTo(outFile)
	outFile.Close()
}

func decode(encodedInputFile string) {
	inFile, _ := os.Open(encodedInputFile)
	defer inFile.Close()

	reader := bufio.NewReader(inFile)
	img, _ := png.Decode(reader)

	sizeOfMessage := steganography.GetMessageSizeFromImage(img) // retrieving message size to decode in the next line

	msg := steganography.Decode(sizeOfMessage, img) // decoding the message from the file
	//decText, err := Decrypt(string(msg), MySecret)
	//if err != nil {
	//	fmt.Println("error decrypting your encrypted text: ", err)
	//}
	//fmt.Println(decText)
	fmt.Println(string(msg))
}

// ToPng converts an image to png
func ToPng(imageBytes []byte) ([]byte, error) {
	contentType := http.DetectContentType(imageBytes)

	switch contentType {
	case "image/png":
	case "image/jpeg":
		img, err := jpeg.Decode(bytes.NewReader(imageBytes))
		if err != nil {
			return nil, errors.Wrap(err, "unable to decode jpeg")
		}

		buf := new(bytes.Buffer)
		if err := png.Encode(buf, img); err != nil {
			return nil, errors.Wrap(err, "unable to encode png")
		}

		return buf.Bytes(), nil
	}

	return nil, fmt.Errorf("unable to convert %#v to png", contentType)
}
