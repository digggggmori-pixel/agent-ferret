package collector

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows"
)

var (
	procNetUserEnum              = modnetapi32.NewProc("NetUserEnum")
	procNetLocalGroupGetMembers  = modnetapi32.NewProc("NetLocalGroupGetMembers")
)

// USER_INFO_2 is the Windows USER_INFO_2 structure
type USER_INFO_2 struct {
	Name         *uint16
	Password     *uint16
	PasswordAge  uint32
	Priv         uint32
	HomeDir      *uint16
	Comment      *uint16
	Flags        uint32
	ScriptPath   *uint16
	AuthFlags    uint32
	FullName     *uint16
	UsrComment   *uint16
	Parms        *uint16
	Workstations *uint16
	LastLogon    uint32
	LastLogoff   uint32
	AcctExpires  uint32
	MaxStorage   uint32
	UnitsPerWeek uint32
	LogonHours   *byte
	BadPwCount   uint32
	NumLogons    uint32
	LogonServer  *uint16
	CountryCode  uint32
	CodePage     uint32
}

// LOCALGROUP_MEMBERS_INFO_3 contains member name
type LOCALGROUP_MEMBERS_INFO_3 struct {
	DomainAndName *uint16
}

const (
	FILTER_NORMAL_ACCOUNT = 0x0002
	UF_ACCOUNTDISABLE     = 0x0002
	UF_LOCKOUT            = 0x0010
	UF_DONT_EXPIRE_PASSWD = 0x10000
	MAX_PREFERRED_LENGTH  = 0xFFFFFFFF
)

// UserAccountCollector collects local user accounts
type UserAccountCollector struct{}

// NewUserAccountCollector creates a new user account collector
func NewUserAccountCollector() *UserAccountCollector {
	return &UserAccountCollector{}
}

// Collect enumerates local user accounts and identifies administrators
func (c *UserAccountCollector) Collect() ([]types.UserAccountInfo, error) {
	logger.Section("User Account Collection")
	startTime := time.Now()

	// Get list of local admin members
	adminMembers := c.getLocalGroupMembers("Administrators")

	var accounts []types.UserAccountInfo

	var buf *byte
	var entriesRead, totalEntries, resumeHandle uint32

	ret, _, _ := procNetUserEnum.Call(
		0, // local server
		2, // level 2 = USER_INFO_2
		uintptr(FILTER_NORMAL_ACCOUNT),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(MAX_PREFERRED_LENGTH),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)

	if ret != 0 && ret != 234 { // 234 = ERROR_MORE_DATA
		logger.Error("NetUserEnum failed: %d", ret)
		return accounts, fmt.Errorf("NetUserEnum failed: %d", ret)
	}

	if buf != nil {
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buf)))
	}

	userInfoSize := unsafe.Sizeof(USER_INFO_2{})
	for i := uint32(0); i < entriesRead; i++ {
		userPtr := (*USER_INFO_2)(unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(i)*userInfoSize))

		name := windows.UTF16PtrToString(userPtr.Name)
		fullName := ""
		if userPtr.FullName != nil {
			fullName = windows.UTF16PtrToString(userPtr.FullName)
		}
		comment := ""
		if userPtr.Comment != nil {
			comment = windows.UTF16PtrToString(userPtr.Comment)
		}

		account := types.UserAccountInfo{
			Name:        name,
			FullName:    fullName,
			Comment:     comment,
			Flags:       userPtr.Flags,
			IsAdmin:     adminMembers[name],
			IsDisabled:  userPtr.Flags&UF_ACCOUNTDISABLE != 0,
			IsLocked:    userPtr.Flags&UF_LOCKOUT != 0,
			PasswordAge: time.Duration(userPtr.PasswordAge) * time.Second,
			LastLogon:   time.Unix(int64(userPtr.LastLogon), 0),
			NumLogons:   userPtr.NumLogons,
			BadPWCount:  userPtr.BadPwCount,
		}

		accounts = append(accounts, account)
		logger.Debug("User: %s (admin=%v, disabled=%v)", name, account.IsAdmin, account.IsDisabled)
	}

	logger.Timing("UserAccountCollector.Collect", startTime)
	logger.Info("User accounts: %d accounts (%d admins)", len(accounts), countAdmins(accounts))

	return accounts, nil
}

func (c *UserAccountCollector) getLocalGroupMembers(group string) map[string]bool {
	members := make(map[string]bool)

	groupPtr, _ := syscall.UTF16PtrFromString(group)
	var buf *byte
	var entriesRead, totalEntries uint32

	ret, _, _ := procNetLocalGroupGetMembers.Call(
		0, // local server
		uintptr(unsafe.Pointer(groupPtr)),
		3, // level 3 = domain\name
		uintptr(unsafe.Pointer(&buf)),
		uintptr(MAX_PREFERRED_LENGTH),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		0, // resume handle
	)

	if ret != 0 || buf == nil {
		return members
	}
	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buf)))

	memberSize := unsafe.Sizeof(LOCALGROUP_MEMBERS_INFO_3{})
	for i := uint32(0); i < entriesRead; i++ {
		memberPtr := (*LOCALGROUP_MEMBERS_INFO_3)(unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(i)*memberSize))
		if memberPtr.DomainAndName != nil {
			fullName := windows.UTF16PtrToString(memberPtr.DomainAndName)
			// Extract username from DOMAIN\Username
			parts := splitDomainUser(fullName)
			members[parts] = true
		}
	}

	return members
}

func splitDomainUser(domainUser string) string {
	for i := len(domainUser) - 1; i >= 0; i-- {
		if domainUser[i] == '\\' {
			return domainUser[i+1:]
		}
	}
	return domainUser
}

func countAdmins(accounts []types.UserAccountInfo) int {
	count := 0
	for _, a := range accounts {
		if a.IsAdmin && !a.IsDisabled {
			count++
		}
	}
	return count
}
