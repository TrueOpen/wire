package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyAminoNames(t *testing.T) {
	path := writeImage(t, `{
	  "file": [
	    {
	      "name": "hub/v1/tx.proto",
	      "package": "hub.v1",
	      "messageType": [{
	        "name": "MsgRegisterBuilder",
	        "options": {"[amino.name]": "trueopen/x/hub/MsgRegisterBuilder"}
	      }],
	      "service": [{
	        "name": "Msg",
	        "method": [{
	          "name": "RegisterBuilder",
	          "inputType": ".hub.v1.MsgRegisterBuilder",
	          "outputType": ".hub.v1.MsgRegisterBuilderResponse"
	        }]
	      }]
	    },
	    {
	      "name": "task/v1/tx.proto",
	      "package": "task.v1",
	      "messageType": [{
	        "name": "MsgCreateSession",
	        "options": {"[amino.name]": "trueopen/x/task/MsgCreateSession"}
	      }],
	      "service": [{
	        "name": "Msg",
	        "method": [{
	          "name": "CreateSession",
	          "inputType": ".task.v1.MsgCreateSession",
	          "outputType": ".task.v1.MsgCreateSessionResponse"
	        }]
	      }]
	    }
	  ]
	}`)
	count, err := verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("count=%d want 2", count)
	}
}

func TestVerifyRejectsMissingAndWrongNames(t *testing.T) {
	for name, option := range map[string]string{
		"missing": "",
		"wrong":   `, "options": {"[amino.name]": "wrong/name"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := writeImage(t, `{
			  "file": [{
			    "name": "hub/v1/tx.proto",
			    "package": "hub.v1",
			    "messageType": [{"name": "MsgThing"`+option+`}],
			    "service": [{
			      "name": "Msg",
			      "method": [{
			        "name": "Thing",
			        "inputType": ".hub.v1.MsgThing",
			        "outputType": ".hub.v1.MsgThingResponse"
			      }]
			    }]
			  }]
			}`)
			_, err := verify(path)
			if err == nil || !strings.Contains(err.Error(), "amino.name") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func writeImage(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.json")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
