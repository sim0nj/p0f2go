package p0f

type Entry struct {
	Section string
	Label   string
	Sys     string
	Sig     []string
}

type DB struct {
	Entries []Entry
}
