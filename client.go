package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"
	"strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	Password string
	DecKey   userlib.PKEDecKey
	SigKey   userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type TreeFileNode struct {
	FileOwner       string
	FileContentUUID uuid.UUID
	FileParent      uuid.UUID
	FileRecipients  map[string]uuid.UUID
}

type FileContent struct {
	ContentUUID     uuid.UUID
	NextContentUUID uuid.UUID
	LastContentUUID uuid.UUID
	Length          int
}

type Invitation struct {
	Username          string
	RecipientUsername string
	TreeFileNodeUUID  uuid.UUID
	AccessKey         []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	if len(username) == 0 {
		return nil, errors.New("username has to be length greater than 0")
	}
	//64 byte hash of username
	hash := userlib.Hash([]byte(username))

	//Create UUID for public key
	pubKeyUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return userdataptr, errors.New("username is not valid")
	}

	_, userExists := userlib.KeystoreGet(string(pubKeyUUID[:16]))
	//Check if public key derived from username already in keystore
	if userExists {
		return userdataptr, errors.New("username already exists")
	} else {
		pubKey, decKey, err := userlib.PKEKeyGen()
		if err != nil {
			return userdataptr, errors.New("could not generate keys")
		}

		//Store public key in keystore
		err = userlib.KeystoreSet(string(pubKeyUUID[:16]), pubKey)
		if err != nil {
			return userdataptr, errors.New("could not store key in keystore")
		}

		//Store verify key in keystore
		signKey, verifyKey, err := userlib.DSKeyGen()
		if err != nil {
			return userdataptr, errors.New("could not generate keys")
		}
		verKeyUUID, err := uuid.FromBytes(hash[16:32])
		if err != nil {
			return userdataptr, errors.New("could get uuid from bytes")
		}
		err = userlib.KeystoreSet(string(verKeyUUID[:16]), verifyKey)
		if err != nil {
			return userdataptr, errors.New("could not store key in keystore")
		}

		//Create User struct
		userdata.Username = username
		userdata.DecKey = decKey
		userdata.SigKey = signKey

		userBytes, err := json.Marshal(userdata)
		if err != nil {
			return userdataptr, errors.New("could not serialize user struct")
		}

		//Encrypt User struct
		salt := userlib.RandomBytes(32)
		passKey := userlib.Argon2Key([]byte(password), salt, 32)
		iv := userlib.RandomBytes(16)
		crypStruct := userlib.SymEnc(passKey[:16], iv, userBytes)
		if err != nil {
			return userdataptr, errors.New("could not encrypt user struct")
		}

		//Create salt and store in DataStore
		saltUUID, err := uuid.FromBytes(hash[32:48])
		if err != nil {
			return userdataptr, errors.New("could not create salt UUID")
		}
		userlib.DatastoreSet(saltUUID, salt)

		//Create HMAC
		hmac, err := userlib.HMACEval(passKey[16:32], crypStruct)
		if err != nil {
			return userdataptr, errors.New("could not create hmac tag")
		}

		//Store encrypted user struct
		structUUID, err := uuid.FromBytes(hash[48:64])
		if err != nil {
			return userdataptr, errors.New("could not create struct UUID")
		}
		userlib.DatastoreSet(structUUID, append(hmac, crypStruct...))
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	//Retrieving user struct UUID and salt UUID
	hash := userlib.Hash([]byte(username))
	structUUID, err := uuid.FromBytes(hash[48:64])
	if err != nil {
		return nil, errors.New("could not create struct UUID")
	}
	saltUUID, err := uuid.FromBytes(hash[32:48])
	if err != nil {
		return nil, errors.New("could not create salt UUID")
	}

	//Retrieving user struct
	crypStruct, userExists := userlib.DatastoreGet(structUUID)
	if !userExists {
		return nil, errors.New("user struct UUID not in datastore")
	}

	if len(crypStruct) < 64 {
		return nil, errors.New("user struct has been tampered with")
	}

	//Was username already initialized
	if userExists {
		//Retrieve salt
		salt, exists := userlib.DatastoreGet(saltUUID)
		if !exists {
			return nil, errors.New("salt UUID not in datastore")
		}

		//Supposed key to decrypt user struct
		susKey := userlib.Argon2Key([]byte(password), salt, 32)

		//Supposed hmac tag
		hmacTag, err := userlib.HMACEval(susKey[16:32], crypStruct[64:])
		if err != nil {
			return nil, errors.New("could not create hmac tag")
		}

		//checking that hmac tag matches up
		areEqual := userlib.HMACEqual(crypStruct[:64], hmacTag)
		if !areEqual {
			return nil, errors.New("user struct hmac tags are not matching up")
		}

		//Unmarshalling struct
		plainStruct := userlib.SymDec(susKey[:16], crypStruct[64:])
		var userStruct User
		json.Unmarshal(plainStruct, &userStruct)

		return &userStruct, nil
	}

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	treeFileUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return errors.New("could not generate uuid for Tree File")
	}

	var treeFileNode TreeFileNode
	var fileContent FileContent
	var accessKey []byte

	_, ok := userlib.DatastoreGet(treeFileUUID)
	//If file exists
	if ok {
		//Get accesskey to decrypt File content struct
		accessKey, err = getAccessKey(filename, userdata)
		if err != nil {
			return err
		}
		//Get Tree File node decrypted and unmarshalled
		treeFileNode, err = getTreeFileNode(filename, userdata)
		if err != nil {
			return err
		}

		unMarshalFileContent, err := VerifyThenDecrypt(treeFileNode.FileContentUUID, "struct", accessKey)
		if err != nil {
			return err
		}
		err = json.Unmarshal(unMarshalFileContent, &fileContent)
		if err != nil {
			return errors.New("file content could not be unmarshalled :(")
		}
		//If creating new file
	} else {
		//Generate accessKey
		accessKey = userlib.RandomBytes(16)

		//Encrypt and HMAC accessKey
		securedKey, err := encryptAccessKey(accessKey, userdata.Username)
		if err != nil {
			return errors.New("could not secure accessKey")
		}
		//Store accessKey in Datastore
		accessKeyUUID, err := uuid.FromBytes([]byte(treeFileUUID.String() + userdata.Username)[:16])
		if err != nil {
			return err
		}

		userlib.DatastoreSet(accessKeyUUID, securedKey)

		//Create TreeFileNode struct
		treeFileNode.FileOwner = userdata.Username
		treeFileNode.FileContentUUID = uuid.New()
		treeFileNode.FileRecipients = make(map[string]uuid.UUID)
		//Encrpyt and HMAC TreeFileNode
		marshalTreeFile, err := json.Marshal(treeFileNode)
		if err != nil {
			return errors.New("tree file could not be marshalled")
		}
		encryptedTree, err := SecureContent(marshalTreeFile, "trees"+userdata.Username, accessKey)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(treeFileUUID, encryptedTree)
		fileContent.ContentUUID = uuid.New()
	}
	//Create and store FileContentStruct
	fileContent.NextContentUUID = uuid.Nil
	fileContent.LastContentUUID = treeFileNode.FileContentUUID
	fileContent.Length = 1
	//Encrypt and HMAC content
	encryptedContent, err := SecureContent(content, "filecontent1", accessKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(fileContent.ContentUUID, encryptedContent)
	//Encrypt and HMAC content
	marshalContentStruct, err := json.Marshal(fileContent)
	if err != nil {
		return err
	}
	encryptedStruct, err := SecureContent(marshalContentStruct, "struct", accessKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(treeFileNode.FileContentUUID, encryptedStruct)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var firstFileContent FileContent
	var oldLastContent FileContent
	accessKey, err := getAccessKey(filename, userdata)
	if err != nil {
		return err
	}

	newContentUUID := uuid.New()
	//Create FileContent struct for new file append
	newStructUUID := uuid.New()
	var newFileContent FileContent
	newFileContent.ContentUUID = newContentUUID
	newFileContent.NextContentUUID = uuid.Nil
	newFileContent.LastContentUUID = newStructUUID
	newFileContent.Length = 0
	//Store new FileContent struct
	marshalNewFileContent, err := json.Marshal(newFileContent)
	if err != nil {
		return errors.New("could not marshal new file content struct")
	}
	encNewFileContent, err := SecureContent(marshalNewFileContent, "struct", accessKey)
	if err != nil {
		return errors.New("could not encrypt and hmac new content struct")
	}
	userlib.DatastoreSet(newStructUUID, encNewFileContent)

	//Decrypt Tree file node to get FileContentUUID
	treeFileNode, err := getTreeFileNode(filename, userdata)
	if err != nil {
		return errors.New("could not retrieve tree file node")
	}
	//Retrieve First Content
	marshalFileContent, err := VerifyThenDecrypt(treeFileNode.FileContentUUID, "struct", accessKey)
	if err != nil {
		return errors.New("could not get file content from Datastore")
	}
	err = json.Unmarshal(marshalFileContent, &firstFileContent)
	if err != nil {
		return errors.New("could not unmarshal file content")
	}
	//Update the LastContentUUID for the first content
	if firstFileContent.Length == 1 {
		//Update the Next Content UUID to the new content struct
		firstFileContent.LastContentUUID = newStructUUID
		firstFileContent.Length = firstFileContent.Length + 1
		firstFileContent.NextContentUUID = newStructUUID
		//Marshal, Encrypt, HMAC updated content struct
		marshalFileContent, err = json.Marshal(firstFileContent)
		if err != nil {
			return errors.New("could not marshal first file content struct")
		}
		encFirstContent, err := SecureContent(marshalFileContent, "struct", accessKey)
		if err != nil {
			return err
		}
		//Store updated, secure struct in Datastore
		userlib.DatastoreSet(treeFileNode.FileContentUUID, encFirstContent)
	} else {
		//Retrieve current last content struct
		marshalLastContent, err := VerifyThenDecrypt(firstFileContent.LastContentUUID, "struct", accessKey)
		if err != nil {
			return errors.New("could not get last content from Datastore")
		}
		err = json.Unmarshal(marshalLastContent, &oldLastContent)
		if err != nil {
			return errors.New("could not unmarshal file content")
		}
		//Check that lastContent.next is nil
		if oldLastContent.NextContentUUID != uuid.Nil {
			return errors.New("last content UUID is incorrect")
		}

		//Update old last content struct with new content info
		oldLastContent.NextContentUUID = newStructUUID
		oldLastContent.LastContentUUID = newStructUUID
		oldLastContent.Length = firstFileContent.Length + 1
		//Marshal, Encrypt, HMAC updated content struct
		marshalLastContent, err = json.Marshal(oldLastContent)
		if err != nil {
			return errors.New("could not marshal first file content struct")
		}
		encLastContent, err := SecureContent(marshalLastContent, "struct", accessKey)
		if err != nil {
			return err
		}
		//Store updated, secure struct in Datastore
		userlib.DatastoreSet(firstFileContent.LastContentUUID, encLastContent)

		//Update the Next Content UUID to the new content struct
		firstFileContent.LastContentUUID = newStructUUID
		firstFileContent.Length = firstFileContent.Length + 1
		//Marshal, Encrypt, HMAC updated content struct
		marshalFileContent, err = json.Marshal(firstFileContent)
		if err != nil {
			return errors.New("could not marshal first file content struct")
		}
		encFirstContent, err := SecureContent(marshalFileContent, "struct", accessKey)
		if err != nil {
			return err
		}
		//Store updated, secure struct in Datastore
		userlib.DatastoreSet(treeFileNode.FileContentUUID, encFirstContent)
	}
	//Encrypt and HMAC new content
	encContent, err := SecureContent(content, "filecontent"+strconv.Itoa(firstFileContent.Length), accessKey)
	if err != nil {
		return err
	}
	//Store new content in DataStore
	userlib.DatastoreSet(newContentUUID, encContent)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//Get Tree File node decrypted and unmarshalled
	treeFileNode, err := getTreeFileNode(filename, userdata)
	if err != nil {
		return nil, err
	}

	//Get accesskey to decrypt File content struct
	accessKey, err := getAccessKey(filename, userdata)
	if err != nil {
		return nil, err
	}

	//Decrypt File Content Struct
	decryptedFileContentStruct, err := VerifyThenDecrypt(treeFileNode.FileContentUUID, "struct", accessKey)
	if err != nil {
		return nil, err
	}

	//Unmarshall File Content Struct
	var fileContent FileContent
	err = json.Unmarshal(decryptedFileContentStruct, &fileContent)
	if err != nil {
		return nil, errors.New("file content could not be unmarshalled :(")
	}

	//Load all of file into one singular variable
	counter := 1
	//Check if current File Content node is empty
	for fileContent.ContentUUID != uuid.Nil {
		//Verify and decrypt File content
		fileContentNode, err := VerifyThenDecrypt(fileContent.ContentUUID, "filecontent"+strconv.Itoa(counter), accessKey)
		if err != nil {
			return nil, err
		}
		//Append file node content
		content = append(content, fileContentNode...)
		if fileContent.NextContentUUID == uuid.Nil {
			break
		}
		//Move onto the next File Content Node
		decryptedFileContentStruct, err := VerifyThenDecrypt(fileContent.NextContentUUID, "struct", accessKey)
		if err != nil {
			return nil, err
		}
		//Unmarshall next File Content Struct
		err = json.Unmarshal(decryptedFileContentStruct, &fileContent)
		if err != nil {
			return nil, errors.New("file content could not be unmarshalled :(")
		}
		counter += 1
	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	treeFileUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return uuid.Nil, errors.New("treeFile uuid could not be generated")
	}

	_, ok := userlib.DatastoreGet(treeFileUUID)
	if !ok {
		return uuid.Nil, errors.New("treefilenode with that name does not exist")
	}

	accessKey, err := getAccessKey(filename, userdata)
	if err != nil {
		return uuid.Nil, errors.New("file does not exist")
	}

	treeFileNode, err := getTreeFileNode(filename, userdata)
	if err != nil {
		return uuid.Nil, errors.New("could not retrieve tree file node for " + userdata.Username)
	}
	treeFileNode.FileRecipients[recipientUsername] = uuid.Nil

	marshalTreeFileNode, err := json.Marshal(treeFileNode)
	if err != nil {
		return uuid.Nil, errors.New("could not marshal tree file node")
	}

	encryoptedTreeFileNode, err := SecureContent(marshalTreeFileNode, "trees"+userdata.Username, accessKey)
	if err != nil {
		return uuid.Nil, errors.New("could not encrypt tree file node")
	}
	userlib.DatastoreSet(treeFileUUID, encryoptedTreeFileNode)

	//Create Invitation struct
	var invitation Invitation
	invitation.Username = userdata.Username
	invitation.RecipientUsername = recipientUsername
	invitation.TreeFileNodeUUID = treeFileUUID
	invitation.AccessKey = accessKey

	//Serialize Invitation struct
	marshalledInviteStruct, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, errors.New("could not marshall inivitation struct")
	}

	//64 byte hash of recipient's username
	hash := userlib.Hash([]byte(recipientUsername))

	//Create UUID for public key
	pubKeyUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return uuid.Nil, errors.New("username is not valid")
	}

	//Get reicipient public key
	publicKey, ok := userlib.KeystoreGet(string(pubKeyUUID[:16]))
	if !ok {
		return uuid.Nil, errors.New("recipient does not exist")
	}

	randomKey := userlib.RandomBytes(16)
	encryptedInvitationStruct, err := SecureContent(marshalledInviteStruct, "invitation", randomKey)
	if err != nil {
		return uuid.Nil, err
	}

	encryptedRandomKey, err := userlib.PKEEnc(publicKey, randomKey)
	if err != nil {
		return uuid.Nil, err
	}

	keyAndInvite := append(encryptedRandomKey, encryptedInvitationStruct...)

	//Sign with User DS
	signature, err := userlib.DSSign(userdata.SigKey, keyAndInvite)
	if err != nil {
		return uuid.Nil, errors.New("could not create inivitation signature")
	}

	signatureAndKeyAndInvite := append(signature, keyAndInvite...)

	//Store in datastore, key UUID is username + recipient username + filename
	hashForInvite := userlib.Hash(append(append([]byte(userdata.Username), []byte(recipientUsername)...), []byte(filename)...))
	hashUUID, err := uuid.FromBytes(hashForInvite[:16])
	userlib.DatastoreSet(hashUUID, signatureAndKeyAndInvite)
	return hashUUID, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	var invitation Invitation
	var parentTreeFile TreeFileNode

	//Retrieve invitation struct from DataStore
	signatureAndKeyAndInvite, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("could not retrieve invitation struct")
	}

	//Verify signature
	if len(signatureAndKeyAndInvite) < 256 {
		return errors.New("invitation is not the correct length")
	}
	signature := signatureAndKeyAndInvite[:256]
	hash := userlib.Hash([]byte(senderUsername))
	verifyKeyUUID, err := uuid.FromBytes(hash[16:32])
	if err != nil {
		return errors.New("could not generate uuid for verify key")
	}
	verifyKey, ok := userlib.KeystoreGet(string(verifyKeyUUID[:16]))
	if !ok {
		return errors.New("could not retrieve verify key")
	}
	err = userlib.DSVerify(verifyKey, signatureAndKeyAndInvite[256:], signature)
	if err != nil {
		return errors.New("signature could not be verified successfully")
	}

	//Decrypt Key
	encKey := signatureAndKeyAndInvite[256:512]
	key, err := userlib.PKEDec(userdata.DecKey, encKey)
	if err != nil {
		return errors.New("could not decrypt symmetric key")
	}

	//Verify and Decrypt Invitation Struct
	marshalInvitationStruct, err := VerifyThenDecrypt(invitationPtr, "invitation", key)
	if err != nil {
		return err
	}
	json.Unmarshal(marshalInvitationStruct, &invitation)

	//Create file in user's namespace
	//Retrieve Parent Tree File
	marshalParentTreeFile, err := VerifyThenDecrypt(invitation.TreeFileNodeUUID, "trees"+senderUsername, invitation.AccessKey)
	if err != nil {
		return errors.New("could not retrieve parent's tree file node")
	}
	json.Unmarshal(marshalParentTreeFile, &parentTreeFile)

	_, ok = parentTreeFile.FileRecipients[userdata.Username]
	if !ok {
		return errors.New("invitation is not valid")
	}

	//Create a treeFileNode for the user
	var newTreeFile TreeFileNode
	newTreeFile.FileOwner = senderUsername
	newTreeFile.FileContentUUID = parentTreeFile.FileContentUUID
	newTreeFile.FileRecipients = make(map[string]uuid.UUID)
	newTreeFileUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return errors.New("could not generate uuid for new tree file")
	}
	//Check if file exists with same name in user space
	_, ok = userlib.DatastoreGet(newTreeFileUUID)
	if ok {
		return errors.New("file with name " + filename + " exists for user " + userdata.Username)
	}
	marshalNewTreeFile, err := json.Marshal(newTreeFile)
	if err != nil {
		return errors.New("could not marshal new tree file")
	}
	encNewTreeFile, err := SecureContent(marshalNewTreeFile, "trees"+userdata.Username, invitation.AccessKey)
	if err != nil {
		return errors.New("could not encrypt and HMAC new tree file")
	}
	userlib.DatastoreSet(newTreeFileUUID, encNewTreeFile)

	//Encrypt and store access key for new user
	encAccessKey, err := encryptAccessKey(invitation.AccessKey, userdata.Username)
	if err != nil {
		return errors.New("could not encrypt and hmac access key")
	}
	accessKeyUUID, err := uuid.FromBytes([]byte(newTreeFileUUID.String() + userdata.Username)[:16])
	if err != nil {
		return errors.New("could not store access key")
	}
	userlib.DatastoreSet(accessKeyUUID, encAccessKey)
	//Update Parent Tree File Recipients
	parentTreeFile.FileRecipients[userdata.Username] = newTreeFileUUID

	marshalParentTreeFile, err = json.Marshal(parentTreeFile)
	if err != nil {
		return errors.New("could not marshal parent tree file")
	}

	secureParentTreeFile, err := SecureContent(marshalParentTreeFile, "trees"+senderUsername, invitation.AccessKey)
	if err != nil {
		return errors.New("could not secure " + senderUsername + "'s tree file for " + userdata.Username)
	}
	userlib.DatastoreSet(invitation.TreeFileNodeUUID, secureParentTreeFile)

	return nil

}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	treeFileUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return errors.New("treeFile uuid could not be generated")
	}

	//Check that user has filename in their namespace
	treeFileNode, err := getTreeFileNode(filename, userdata)
	if err != nil {
		return errors.New("tould not find TreeFileNode")
	}

	//Check that recipient has filename in their namespace
	recipientTreeFileNodeUUID, shared := treeFileNode.FileRecipients[recipientUsername]
	if shared {
		//Get accessKey
		accessKey, err := getAccessKey(filename, userdata)
		if err != nil {
			return errors.New("could not generate access key")
		}
		if treeFileNode.FileRecipients[recipientUsername] != uuid.Nil {
			//Delete TreeFileNode Struct recipient user and all users that they shared it to
			err = deleteSharedUsersRecursively(recipientTreeFileNodeUUID, accessKey, recipientUsername)
			if err != nil {
				return errors.New("could not delete shared users")
			}
		}

		//Delete revoked user from the map of file recipients
		delete(treeFileNode.FileRecipients, recipientUsername)

		//Create new accessKey
		newAccessKey := userlib.RandomBytes(16)
		//Encrypt and HMAC new accessKey
		securedKey, err := encryptAccessKey(newAccessKey, userdata.Username)
		if err != nil {
			return errors.New("could not secure accessKey")
		}
		//Store new accessKey in Datastore
		accessKeyUUID, err := uuid.FromBytes([]byte(treeFileUUID.String() + userdata.Username)[:16])
		if err != nil {
			return err
		}
		userlib.DatastoreSet(accessKeyUUID, securedKey)

		//Save old file content UUID and make a new one and encrypt the tree with the new key and set it
		oldUUID := treeFileNode.FileContentUUID
		treeFileNode.FileContentUUID = uuid.New()
		marshalTreeFile, err := json.Marshal(treeFileNode)
		if err != nil {
			return errors.New("tree file could not be marshalled")
		}
		encryptedTree, err := SecureContent(marshalTreeFile, "trees"+userdata.Username, newAccessKey)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(treeFileUUID, encryptedTree)

		newfirstFileContentStructUUID := treeFileNode.FileContentUUID
		err = changeEveryUUID(oldUUID, uuid.New(), uuid.New(), userdata, newAccessKey, accessKey, 1, newfirstFileContentStructUUID)
		if err != nil {
			return errors.New("could not change every UUID")
		}

		//Change every shared users first fileContentStruct to new uuid
		for user, treeUUID := range treeFileNode.FileRecipients {
			err = updateSharedUsers(newfirstFileContentStructUUID, newAccessKey, accessKey, user, treeUUID)
			if err != nil {
				return err
			}
		}

	} else {
		return errors.New("this file is currently not shared with recipient")
	}

	return nil
}

func changeEveryUUID(curr uuid.UUID, next uuid.UUID, last uuid.UUID, userdata *User, newKey []byte, oldKey []byte, counter int, newUUID uuid.UUID) (err error) {
	decryptedFileContentStruct, err := VerifyThenDecrypt(curr, "struct", oldKey)
	if err != nil {
		return errors.New("could not decrypt file content struct")
	}
	var fileContentStruct FileContent
	err = json.Unmarshal(decryptedFileContentStruct, &fileContentStruct)
	if err != nil {
		return errors.New("could not unmarhsall file content struct")
	}

	var oldContentUUID uuid.UUID
	isLast := false
	if fileContentStruct.NextContentUUID != uuid.Nil {
		fileContentStruct.NextContentUUID = next
	} else {
		isLast = true
	}
	fileContentStruct.LastContentUUID = last
	oldContentUUID = fileContentStruct.ContentUUID
	fileContentStruct.ContentUUID = uuid.New()

	fileContent, err := VerifyThenDecrypt(oldContentUUID, "filecontent"+strconv.Itoa(counter), oldKey)
	if err != nil {
		return errors.New("could not decrypt file content")
	}

	encryptedFileContent, err := SecureContent(fileContent, "filecontent"+strconv.Itoa(counter), newKey)
	if err != nil {
		return errors.New("could not encrypt file content")
	}

	userlib.DatastoreSet(fileContentStruct.ContentUUID, encryptedFileContent)
	userlib.DatastoreDelete(oldContentUUID)
	userlib.DatastoreDelete(curr)

	masrhsallFileContentStruct, err := json.Marshal(fileContentStruct)
	if err != nil {
		return errors.New("could not unmarhsall file content struct")
	}

	encryptedFileContentStruct, err := SecureContent(masrhsallFileContentStruct, "struct", newKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(newUUID, encryptedFileContentStruct)

	if !isLast {
		changeEveryUUID(oldContentUUID, uuid.New(), uuid.New(), userdata, newKey, oldKey, counter+1, uuid.New())
	}
	return nil
}

func updateSharedUsers(newfirstFileContentStructUUID uuid.UUID, newAccessKey []byte, oldAccessKey []byte, username string, treeFileUUID uuid.UUID) (err error) {
	var treeFileNode TreeFileNode
	//Decrypt treeFileNode for user
	unMarshalTreeNode, err := VerifyThenDecrypt(treeFileUUID, "trees"+username, oldAccessKey)
	if err != nil {
		return errors.New("could not retrieve " + username + "'s tree file node")
	}
	err = json.Unmarshal(unMarshalTreeNode, &treeFileNode)
	if err != nil {
		return errors.New("could not unmarshal tree file node for " + username)
	}
	//Update contentUUID in their treeFileNode
	treeFileNode.FileContentUUID = newfirstFileContentStructUUID
	//Update accessKey using the user's accessKeyUUID
	accessKeyUUID, err := uuid.FromBytes([]byte(treeFileUUID.String() + username)[:16])
	if err != nil {
		return errors.New("key uuid could not be generated for " + username)
	}
	encNewAccessKey, err := encryptAccessKey(newAccessKey, username)
	if err != nil {
		return errors.New("could not encrypt access key")
	}
	userlib.DatastoreSet(accessKeyUUID, encNewAccessKey)
	//Encrypt their treeFileNode using the new accessKey
	marshalTreeNode, err := json.Marshal(treeFileNode)
	if err != nil {
		return errors.New("failed to marshal " + username + "'s tree file node")
	}
	secureTreeNode, err := SecureContent(marshalTreeNode, "trees"+username, newAccessKey)
	if err != nil {
		return errors.New("failed to secure " + username + "'s tree file node")
	}
	userlib.DatastoreSet(treeFileUUID, secureTreeNode)
	for user, treeUUID := range treeFileNode.FileRecipients {
		err = updateSharedUsers(newfirstFileContentStructUUID, newAccessKey, oldAccessKey, user, treeUUID)
		if err != nil {
			return errors.New("failed to update user " + user)
		}
	}

	return nil
}

func deleteSharedUsersRecursively(treeFileNodeUUID uuid.UUID, key []byte, username string) (err error) {
	//verify and decrypt treeFileNode struct
	decryptedTreeFileNode, err := VerifyThenDecrypt(treeFileNodeUUID, "trees"+username, key)
	if err != nil {
		return errors.New("could not decrypt recipient treeFileNode")
	}

	//unmarshall TreeFileNode
	var treeFileNode TreeFileNode
	err = json.Unmarshal(decryptedTreeFileNode, &treeFileNode)
	if err != nil {
		return errors.New("could not unmarshall recipient treeFileNode")
	}

	//Get all users person has shared file with
	theirSharedUsers := treeFileNode.FileRecipients
	//Delete TreeFileNode of this user
	userlib.DatastoreDelete(treeFileNodeUUID)

	//Call function on each shared user
	for user := range theirSharedUsers {
		deleteSharedUsersRecursively(theirSharedUsers[user], key, user)
	}

	return nil
}

func SecureContent(content []byte, purpose string, key []byte) (securedContent []byte, err error) {
	var kdfKey []byte
	kdfKey, err = userlib.HashKDF(key, []byte(purpose))
	if err != nil {
		return nil, errors.New("could not generate key using HashKDF")
	}

	iv := userlib.RandomBytes(16)
	encContent := userlib.SymEnc(kdfKey[:16], iv, content)
	hmac, err := userlib.HMACEval(kdfKey[16:32], encContent)
	if err != nil {
		return nil, errors.New("could not HMAC content")
	}

	return append(hmac, encContent...), nil
}

func VerifyThenDecrypt(contentUUID uuid.UUID, purpose string, key []byte) (plaintext []byte, err error) {
	var kdfKey []byte
	kdfKey, err = userlib.HashKDF(key, []byte(purpose))
	if err != nil {
		return nil, errors.New("could not get key")
	}
	contentHMAC, ok := userlib.DatastoreGet(contentUUID)
	if !ok {
		return nil, errors.New("content does not exist")
	}
	if purpose == "invitation" {
		contentHMAC = contentHMAC[512:]
	}
	if purpose == "secure" {
		contentHMAC = contentHMAC[256:]
	}
	hmacTag := contentHMAC[:64]
	encContent := contentHMAC[64:]
	content := userlib.SymDec(kdfKey[:16], encContent)
	generatedHMAC, err := userlib.HMACEval(kdfKey[16:32], encContent)
	if err != nil {
		return nil, errors.New("hmac could not be generated")
	}
	equal := userlib.HMACEqual(hmacTag, generatedHMAC)
	if !equal {
		return nil, errors.New("hmac is not equal, content is tampered with")
	}
	return content, nil
}

func getTreeFileNode(filename string, userdata *User) (treeFileNode TreeFileNode, err error) {
	//Get TreeFileUUID
	treeFileUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return treeFileNode, err
	}
	//Get accessKey
	accessKey, err := getAccessKey(filename, userdata)
	if err != nil {
		return treeFileNode, errors.New("could not generate access key")
	}
	//verify and decrypt treeFileNode struct
	decryptedTreeFileNode, err := VerifyThenDecrypt(treeFileUUID, "trees"+userdata.Username, accessKey)
	if err != nil {
		return treeFileNode, err
	}

	//unmarshall TreeFileNode
	err = json.Unmarshal(decryptedTreeFileNode, &treeFileNode)
	if err != nil {
		return treeFileNode, err
	}

	return treeFileNode, nil
}

func getAccessKey(filename string, userdata *User) (key []byte, err error) {
	treeFileUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, errors.New("treeFile uuid could not be generated")
	}
	accessKeyUUID, err := uuid.FromBytes([]byte(treeFileUUID.String() + userdata.Username)[:16])
	if err != nil {
		return nil, errors.New("key uuid could not be generated")
	}
	symAndAccess, ok := userlib.DatastoreGet(accessKeyUUID)
	if !ok {
		return nil, errors.New("could get retrieve" + userdata.Username + "'s access key")
	}
	encSymKey := symAndAccess[:256]
	symKey, err := userlib.PKEDec(userdata.DecKey, encSymKey)

	if err != nil {
		return nil, errors.New("could not decrypt sym key for " + userdata.Username)
	}
	accessKey, err := VerifyThenDecrypt(accessKeyUUID, "secure", symKey)
	if err != nil {
		return nil, errors.New("accessKey could not be decrypted and verified for " + userdata.Username)
	}

	return accessKey, nil
}

func encryptAccessKey(accessKey []byte, username string) (encAccessKey []byte, err error) {
	//Generate symmetric key
	symKey := userlib.RandomBytes(16)
	//Get user's public key
	curHash := userlib.Hash([]byte(username))
	pubKeyUUID, err := uuid.FromBytes(curHash[:16])
	if err != nil {
		return nil, errors.New("could not generate uuid for " + username + "'s public key")
	}
	pubKey, ok := userlib.KeystoreGet(string(pubKeyUUID[:16]))
	if !ok {
		return nil, errors.New("could not retrieve " + username + "'s public key")
	}
	//Publicly encrypt sym Key
	encSymKey, err := userlib.PKEEnc(pubKey, symKey)
	if err != nil {
		return nil, errors.New("could not encrypt " + username + "'s sym key")
	}
	//Enc and HMAC accessKey
	encAccessKey, err = SecureContent(accessKey, "secure", symKey)
	if err != nil {
		return nil, errors.New("could not encrypt " + username + "'s access key")
	}
	return append(encSymKey, encAccessKey...), nil
}
