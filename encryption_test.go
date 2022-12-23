package main

import (
	"crypto/aes"
	"errors"
	"testing"
)

func FuzzEncryptAESDecryptAES(f *testing.F) {
	type args struct {
		key       []byte
		plainText []byte
	}
	tests := []args{
		{
			[]byte("s0mer/\\ndomK_e_y"),
			[]byte(`Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.`),
		},
		{
			[]byte("dummyPassPassdumdummyPassPassdum"),
			[]byte(`Beperkt elk goa javanen ton vreemde bewerkt vreezen gedaald. Verwoest en mijnerts na bespaart ze en. Waarde en is tonnen ze bekend gevolg soegei gelukt. In voldoen fortuin ad tapioca bewerkt nu tinmijn of. Men nacht rente zee wonen dan. Millioenen opgegraven ontwouding in te. Na staatjes in waardoor verdeeld ongeveer ik systemen. Tinmijn hoeveel en al grooter inkomen te. Gebied europa er ringen gelden velden is legden er. Reden hun rug douai niets toe weten weg. `),
		},
		{
			[]byte("dummyPassPassdum"),
			[]byte(`Beperkt elk goa javanen ton vreemde bewerkt vreezen gedaald. Verwoest en mijnerts na bespaart ze en. Waarde en is tonnen ze bekend gevolg soegei gelukt. In voldoen fortuin ad tapioca bewerkt nu tinmijn of. Men nacht rente zee wonen dan. Millioenen opgegraven ontwouding in te. Na staatjes in waardoor verdeeld ongeveer ik systemen. Tinmijn hoeveel en al grooter inkomen te. Gebied europa er ringen gelden velden is legden er. Reden hun rug douai niets toe weten weg. `),
		},
	}
	for _, tc := range tests {
		f.Add(tc.key, tc.plainText)
	}
	f.Fuzz(func(t *testing.T, key []byte, plainText []byte) {
		encd, err := EncryptAES(key, plainText)
		if err != nil {
			t.Logf("faild to EncryptAES %v", err)
			var errx aes.KeySizeError
			if !errors.As(err, &errx) {
				t.Errorf("faild to EncryptAES %v", err)
			}
		}

		if err == nil {
			decd, err := DecryptAES(key, encd)
			if err != nil {
				t.Errorf("faild to DecryptAES %v", err)
				return
			}

			if string(decd) != string(plainText) {
				t.Errorf("Before: %s, after: %s", string(plainText), string(decd))
			}
		}
	})
}
