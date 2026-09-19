package entity

type Reauthentication struct{ Method, Password, IdToken, Code, State string }
