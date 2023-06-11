package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ini buat sturck usernya
// bson fungsinya untuk mapping ke database Efisiensi: BSON umumnya lebih efisien dalam hal ukuran file dan kecepatan pemrosesan daripada JSON dalam konteks Go. Karena BSON adalah format biner, pengodean dan dekodean data BSON dapat dilakukan dengan cepat. JSON membutuhkan parsing dan serialisasi yang lebih kompleks karena format teksnya.
// Dalam prakteknya, JSON lebih umum digunakan untuk pertukaran data antar sistem yang berbeda, sementara BSON sering digunakan dalam konteks database MongoDB untuk menyimpan dan mengambil data secara efisien.
type User struct {
	ID            primitive.ObjectID `bson:"_id"`
	First_name    *string            `json:"first_name" validate:"required,min=2,max=100"`   //validasi required yang di perlukan, min 2 karakter, max 100
	Last_name     *string            `json:"last_name" validate:"required,min=2,max=100"`    //validasi required yang di perlukan, min 2 karakter, max 100
	Password      *string            `json:"password" validate:"required,min=6"`             //validasi required yang di perlukan, min 2 karakter
	Email         *string            `json:"email" validate:"email,required"`                //validasi required yang di perlukan email wajib
	Phone         *string            `json:"phone" validate:"required"`                      //validasi required yang di perlukan password wajib
	Token         *string            `json:"token"`                                          //validasi required yang di perlukan token wajib
	User_type     *string            `json:"user_type" validate:"required,eq=ADMIN|ew=USER"` //penggunaan enum Ini adalah aturan validasi yang menentukan bahwa field ini harus sama dengan "ADMIN" atau harus diakhiri dengan "USER". Jadi, validasi akan berhasil jika nilai field ini adalah "ADMIN" atau nilainya diakhiri dengan "USER", seperti "SUPERUSER" atau "GUESTUSER". Namun, jika nilainya bukan "ADMIN" atau tidak diakhiri dengan "USER", maka validasi akan gagal.
	Refresh_token *string            `json:"refresh_token"`                                  //validasi required yang di perlukan refresh token wajib
	Created_at    time.Time          `json:"created_at"`                                     //validasi required yang di perlukan created at wajib
	Updated_at    time.Time          `json:"updated_at"`                                     //validasi required yang di perlukan updated at wajib
	User_id       *string            `json:"user_id"`                                        //validasi required yang di perlukan user id wajib
}
