package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// Helper function to measure bandwidth of a particular operation

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const overwriteContent = "Lebron is the GOAT"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var antony *client.User
	var monisPelonis *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	antonyFile := "antonyFile.txt"
	monisPelonisFile := "pelonis.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	measureBandwidth := func(probe func()) (bandwidth int) {
		before := userlib.DatastoreGetBandwidth()
		probe()
		after := userlib.DatastoreGetBandwidth()
		return after - before
	}

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			println()
			println("Basic Test: Testing InitUser/GetUser on a single user.")

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			Expect(alice).To(Equal(aliceLaptop))

			println()
		})

		Specify("Basic Test: Testing InitUser error checks (existing/empty usernames).", func() {
			println("Basic Test: Testing InitUser error checks (existing/empty usernames).")
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user also named Alice.")
			bob, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user with no name.")
			bob, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
			println()
		})

		Specify("Basic Test: Testing GetUser error checks.", func() {
			println("Basic Test: Testing GetUser error checks.")
			userlib.DebugMsg("Getting user Alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user named Alice.")
			bob, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			bob, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice with wrong password.")
			bob, err = client.GetUser("alice", contentOne)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting user Alice with wrong username.")
			bob, err = client.GetUser("notalice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting user Antony that does not exist.")
			bob, err = client.GetUser("antony", defaultPassword)
			Expect(err).ToNot(BeNil())

			println()

		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			println("Basic Test: Testing Single User Store/Load/Append.")

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			println()
		})

		Specify("Basic Test: Testing Load File and Append File error checks (filename does not exist in namespace).", func() {
			println("Basic Test: Testing Single User Store/Load/Append.")

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			println()
		})

		Specify("Basic Test: Testing Single User Store/Load/Append/Store/Load.", func() {
			println("Basic Test: Testing Single User Store/Load/Append/Store/Load.")

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Storing file data: %s", overwriteContent)
			err = alice.StoreFile(aliceFile, []byte(overwriteContent))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(overwriteContent)))

			println()
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			println("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.")

			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			println()
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			println("Basic Test: Testing Revoke Functionality")

			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			antony, err = client.InitUser("antony", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			invite2, err := alice.CreateInvitation(aliceFile, "antony")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			err = antony.AcceptInvitation("alice", invite2, antonyFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Antony can load the file.")
			data, err = antony.LoadFile(antonyFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting file share from Bob")
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Anthony attempting to accept invitation that's not his")
			err = antony.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Antony can still load the file.")
			data, err = antony.LoadFile(antonyFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that antony can still append to the file.")
			err = antony.AppendToFile(antonyFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Checking that antony can still overwrite the file.")
			err = antony.StoreFile(antonyFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			println()
		})

		Specify("Basic Test: Testing Accept Invite using same file name already in use.", func() {
			println()
			println("Basic Test: Testing Accept Invite using same file name already in use.")

			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			antony, err = client.InitUser("antony", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Antony storing file %s with content: %s", antonyFile, contentOne)
			err = antony.StoreFile(antonyFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob storing file %s with content: %s", aliceFile, contentOne)
			err = bob.StoreFile((bobFile), []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob cannot accept invite from Alice under same filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Antony creating invite for alice")
			invite2, err := antony.CreateInvitation(antonyFile, "alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice accepting invite for filename %s", "aliceFile2.txt")
			err = aliceDesktop.AcceptInvitation("antony", invite2, "aliceFile2.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking Alice can see content on another session")
			data, err := aliceLaptop.LoadFile("aliceFile2.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			println()
		})

		Specify("Basic Test: Testing Store File Functionality after accepting invite with multiple users and multiple instances.", func() {
			println()
			println("Basic Test: Testing Store File Functionality after accepting invite with multiple users and multiple instances.")

			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing to file %s, content: %s", bobFile, overwriteContent)
			err = bob.StoreFile(bobFile, []byte(overwriteContent))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(overwriteContent)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(overwriteContent)))

			println()
		})

		Specify("Security Test: Testing if attacker changed the invitation struct.", func() {
			println()
			println("Security Test: Testing if attacker changed the invitation struct.")

			userlib.DebugMsg("Initializing users Alice (aliceDesktop), Bob, and Antony.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Changing invitation struct in datastore")
			userlib.DatastoreSet(invite, []byte("I'm in."))

			userlib.DebugMsg("Bob can't accept invitation because it has been tampered with")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			ds := userlib.DatastoreGetMap()
			ds[invite][2] = 0x21

			userlib.DebugMsg("Bob can't accept invitation because it has been tampered with")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			println()
		})

		Specify("Basic Test: Testing functions on nonexistent things.", func() {
			println()
			println("Basic Test: Testing functions on nonexistent things.")

			userlib.DebugMsg("Initializing user Alice and Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			_, err = client.GetUser("Eli", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice loading nonexistent file")
			_, err := alice.LoadFile("doesntExist.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice appending to nonexistent file")
			err = alice.AppendToFile("doesntExist.txt", []byte(contentOne))
			Expect(err).ToNot(BeNil())

			//revoke access to file that doesnt exist
			userlib.DebugMsg("Alice revoking access to Bob a file that does not exist")
			err = alice.RevokeAccess("doesntExist.txt", "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invitation to nonexistent file")
			_, err = alice.CreateInvitation("doesntExist.txt", "bob")
			Expect(err).ToNot(BeNil())

			println()
		})

		Specify("Security Test: Cannot impersonate invitation sender.", func() {
			println()
			println("Security Test: Cannot impersonate invitation sender.")

			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob and Antony.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			antony, err = client.InitUser("antony", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Antony attempting to create invitation to a file he does not have in namespace")
			_, err = antony.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invitation for Bob")
			invite, err := aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob attempting to accept invitation with the name Alice")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob creating invite for antony")
			invite2, err := bob.CreateInvitation(bobFile, "antony")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Antony attempting to accept invitation with the name Alice")
			err = antony.AcceptInvitation("alice", invite2, antonyFile)
			Expect(err).ToNot(BeNil())

			println()
		})

		Specify("Security Test: Revoked user can no longer send invitation.", func() {
			println()
			println("Security Test: Revoked user can no longer send invitation.")

			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob and Antony.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			antony, err = client.InitUser("antony", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invitation for Bob")
			invite, err := aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invitation")
			err = bob.AcceptInvitation("alice", invite, "test")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking access to Bob")
			aliceDesktop.RevokeAccess(aliceFile, "bob")

			userlib.DebugMsg("Bob attempting to invite Antony")
			_, err = bob.CreateInvitation("test", "antony")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob attempting to accept invitation again after being revoked")
			err = bob.AcceptInvitation("alice", invite, "test")
			Expect(err).ToNot(BeNil())

			println()
		})

		Specify("Security Test: Revoked user can no longer accept invitation.", func() {
			println()
			println("Security Test: Revoked user can no longer accept invitation.")

			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob and Antony.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			antony, err = client.InitUser("antony", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invitation for Bob")
			invite, err := aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking access to Bob")
			err = aliceDesktop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob can no longer accept invitation")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob attempting to invite Antony")
			_, err = bob.CreateInvitation("test", "antony")
			Expect(err).ToNot(BeNil())

			println()
		})

		Specify("Efficiency Test: Efficiency of Append", func() {
			println()
			println("Efficiency Test: Efficiency of Append")
			userlib.DebugMsg("Initializing user Monis.")
			monisPelonis, err = client.InitUser("monis", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = monisPelonis.StoreFile(monisPelonisFile, []byte(contentOne))
			Expect(err).To(BeNil())

			ogBandwidth := measureBandwidth(func() {
				userlib.DebugMsg("Check bandwidth before many appends")
				err = monisPelonis.AppendToFile(monisPelonisFile, []byte(overwriteContent))
				Expect(err).To(BeNil())
			})

			for i := 0; i < 750; i++ {
				err = monisPelonis.AppendToFile(monisPelonisFile, []byte(overwriteContent))
				Expect(err).To(BeNil())
			}

			bandAfter750 := measureBandwidth(func() {
				userlib.DebugMsg("Check bandwidth after many appends")
				err = monisPelonis.AppendToFile(monisPelonisFile, []byte(overwriteContent))
				Expect(err).To(BeNil())
			})
			Expect(bandAfter750-ogBandwidth < 375)
			Expect(bandAfter750 < len(overwriteContent)*750)

			println()
		})

		Specify("Malicious file tampering", func() {
			println()
			println("Malicious file tampering")
			userlib.DebugMsg("Initializing user Monis.")
			monisPelonis, err = client.InitUser("monis", defaultPassword)
			Expect(err).To(BeNil())

			dataStoreBefore := userlib.DatastoreGetMap()

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = monisPelonis.StoreFile(monisPelonisFile, []byte(contentOne))
			Expect(err).To(BeNil())

			dataStoreAfter := userlib.DatastoreGetMap()

			for key := range dataStoreAfter {
				_, ok := dataStoreBefore[key]
				if !ok {
					dataStoreAfter[key][66] = 0x37
					_, err := monisPelonis.LoadFile(monisPelonisFile)
					Expect(err).ToNot(BeNil())
				}
			}
			println()

		})

		Specify("Security Test: Invite user on one session, revoke on another.", func() {
			println()
			println("Security Test: Invite user on one session, revoke on another.")

			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob and Monis and Antony.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			monisPelonis, err = client.InitUser("monis", defaultPassword)
			Expect(err).To(BeNil())

			antony, err = client.InitUser("antony", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invitation for Bob")
			bobInvite, err := aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invitation for Monis")
			monisInvite, err := aliceLaptop.CreateInvitation(aliceFile, "monis")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", bobInvite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Monis accepting invite")
			err = monisPelonis.AcceptInvitation("alice", monisInvite, monisPelonisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Monis creating invitation for Antony")
			antonyInvite, err := monisPelonis.CreateInvitation(monisPelonisFile, "antony")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Antony accepting invite")
			err = antony.AcceptInvitation("monis", antonyInvite, antonyFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking access to Bob")
			err = aliceLaptop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that AliceLaptop can still load the file.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that AliceDesktop can still load the file.")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob cannot load the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Monis can still load the file.")
			data, err = monisPelonis.LoadFile(monisPelonisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Antony can still load the file.")
			data, err = antony.LoadFile(antonyFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			println()
		})

		Specify("Security Test: Testing for hash collisions.", func() {
			println()
			println("Security Test: Testing for hash collisions.")

			userlib.DebugMsg("Initializing users Bob and Antony.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			antony, err = client.InitUser("antony", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = antony.StoreFile("almostthis.txt", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "Lebron is the GOAT!")
			err = bob.StoreFile("lmostthis.txt", []byte("Lebron is the GOAT!"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := antony.LoadFile("almostthis.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Loading file...")
			data2, err := bob.LoadFile("lmostthis.txt")
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte("Lebron is the GOAT!")))

			println()
		})

	})
})
