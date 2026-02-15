package collector

import (
	"fmt"
	"runtime"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// WMIQueryFields executes a WQL query and extracts specific fields from each result.
// Returns results as []map[string]string.
func WMIQueryFields(namespace, query string, fields []string) ([]map[string]string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		// S_FALSE (already initialized) is OK
		if oleErr, ok := err.(*ole.OleError); ok && oleErr.Code() == 0x00000001 {
			// already initialized, continue
		} else if err != nil {
			return nil, fmt.Errorf("CoInitializeEx: %w", err)
		}
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return nil, fmt.Errorf("create WbemLocator: %w", err)
	}
	defer unknown.Release()

	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, fmt.Errorf("query IDispatch: %w", err)
	}
	defer wmi.Release()

	serviceRaw, err := oleutil.CallMethod(wmi, "ConnectServer", nil, namespace)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", namespace, err)
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	resultRaw, err := oleutil.CallMethod(service, "ExecQuery", query)
	if err != nil {
		return nil, fmt.Errorf("ExecQuery: %w", err)
	}
	result := resultRaw.ToIDispatch()
	defer result.Release()

	countVal, err := oleutil.GetProperty(result, "Count")
	if err != nil {
		return nil, fmt.Errorf("get Count: %w", err)
	}
	count := int(countVal.Val)

	var rows []map[string]string
	for i := 0; i < count; i++ {
		itemRaw, err := oleutil.CallMethod(result, "ItemIndex", i)
		if err != nil {
			continue
		}
		item := itemRaw.ToIDispatch()

		row := make(map[string]string)
		for _, field := range fields {
			val, err := oleutil.GetProperty(item, field)
			if err == nil && val.Value() != nil {
				row[field] = fmt.Sprintf("%v", val.Value())
			}
		}
		item.Release()
		rows = append(rows, row)
	}

	return rows, nil
}
