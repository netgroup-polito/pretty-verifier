package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

var verbose = false
var injectNoConstrains = false
var injectShuffleReturnType = false
var injectShuffleBoundChecksOperator = false
var injectOffsetBoundCheck = false

// cannot_pass_map_type generation
var injectGetHelperCompactMaps = false
var injectGetHelperCompatMapTypes = false
var injectGenerateRemoveFlag = false

// very present
var injectGenCompatibleRegTypes = false

// var injectCompatibleHelpers = false  //makes the program crash
var injectGenRandBpfHelperCall = false
var injectGenRandBpfCtxAccess = false
var injectGenRandReturnVal = false

var injectFixSpinlock = false
var injectFixRef = false

var injectionFlags = []*bool{
	&injectNoConstrains,
	&injectShuffleReturnType,
	&injectShuffleBoundChecksOperator,
	&injectOffsetBoundCheck,
	&injectGetHelperCompactMaps,
	&injectGetHelperCompatMapTypes,
	&injectGenerateRemoveFlag,
	&injectGenCompatibleRegTypes,
	&injectGenRandBpfHelperCall,
	&injectGenRandBpfCtxAccess,
	&injectGenRandReturnVal,
	&injectFixSpinlock,
	&injectFixRef,
}

var injectionFlagNames = []string{
	"injectNoConstrains",
	"injectShuffleReturnType",
	"injectShuffleBoundChecksOperator",
	"injectOffsetBoundCheck",
	"injectGetHelperCompactMaps",
	"injectGetHelperCompatMapTypes",
	"injectGenerateRemoveFlag",
	"injectGenCompatibleRegTypes",
	"injectGenRandBpfHelperCall",
	"injectGenRandBpfCtxAccess",
	"injectGenRandReturnVal",
	"injectFixSpinlock",
	"injectFixRef",
}

type BpfRuntimeFuzzer struct {
	isEnabled bool
	workDir   string

	helperFuncMap map[string]*BpfHelper
	progTypeMap   map[BpfProgTypeEnum]*BpfProgType
	ctxAccessMap  map[BpfProgTypeEnum]*BpfCtxAccess
}

// Struct per tracciare contatore e generatori
type ErrorStats struct {
	Count      int
	Generators map[string]int
}

type randGen struct {
	*rand.Rand
}

func (r *randGen) nOutOf(n, outOf int) bool {
	if n <= 0 || n >= outOf {
		panic("bad probability")
	}
	v := r.Intn(outOf)
	return v < n
}

func newRand(rs rand.Source) *randGen {
	return &randGen{
		Rand: rand.New(rs),
	}
}

func NewBpfRuntimeFuzzer(enable bool) *BpfRuntimeFuzzer {
	brf := new(BpfRuntimeFuzzer)

	if !enable {
		return brf
	}

	brf.workDir = "./workdir"
	if err := os.Mkdir(brf.workDir, 0755); err != nil && !os.IsExist(err) {
		fmt.Printf("failed to create dir: %v", err)
		os.Exit(-1)
	}

	brf.isEnabled = true
	brf.helperFuncMap = make(map[string]*BpfHelper)
	brf.progTypeMap = make(map[BpfProgTypeEnum]*BpfProgType)
	brf.ctxAccessMap = make(map[BpfProgTypeEnum]*BpfCtxAccess)

	brf.InitFromSrc(HelperFuncMap, ProgTypeMap, CtxAccessMap)

	return brf
}

func (brf *BpfRuntimeFuzzer) IsEnabled() bool {
	return brf.isEnabled
}

/*func (brf *BpfRuntimeFuzzer) GenPrologue(r *randGen, s *state, prog *Prog) {
	var p *BpfProg

	if !brf.isEnabled {
		return
	}

	p = brf.genSeedBpfProg(r)

	c0 := genBpfProgOpenCall(r, s, p)
	s.analyze(c0)
	prog.Calls = append(prog.Calls, c0)

	c1 := genBpfProgLoadCall(r, s, p)
	s.analyze(c1)
	prog.Calls = append(prog.Calls, c1)

	c2 := genBpfProgAttachCall(r, s, p)
	s.analyze(c2)
	prog.Calls = append(prog.Calls, c2)

	c3 := genBpfProgTestRunCall(r, s, p, c1.Ret)
	s.analyze(c3)
	prog.Calls = append(prog.Calls, c3)
}

func genBpfProgOpenCall(r *randGen, s *state, p *BpfProg) *Call {
	meta := r.target.SyscallMap["syz_bpf_prog_open"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	pathStr := []byte(p.BasePath + ".o")
	pathArg := meta.Args[0]
	pathPtr := pathArg.Type.(*PtrType)
	pathBuffer := pathPtr.Elem.(*BufferType)
	pathBufferDir := pathPtr.ElemDir
	pathBufferArg := MakeDataArg(pathBuffer, pathBufferDir, pathStr)
	args[0] = r.allocAddr(s, pathArg.Type, pathArg.Dir(DirIn), pathBufferArg.Size(), pathBufferArg)

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

func genBpfProgLoadCall(r *randGen, s *state, p *BpfProg) *Call {
	meta := r.target.SyscallMap["syz_bpf_prog_load"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	pathStr := []byte(p.BasePath + ".o")
	pathArg := meta.Args[0]
	pathPtr := pathArg.Type.(*PtrType)
	pathBuffer := pathPtr.Elem.(*BufferType)
	pathBufferDir := pathPtr.ElemDir
	pathBufferArg := MakeDataArg(pathBuffer, pathBufferDir, pathStr)
	args[0] = r.allocAddr(s, pathArg.Type, pathArg.Dir(DirIn), pathBufferArg.Size(), pathBufferArg)
	args[1], _ = r.generateArg(s, meta.Args[1].Type, meta.Args[1].Dir(DirIn))

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

func genBpfProgAttachCall(r *randGen, s *state, p *BpfProg) *Call {
	meta := r.target.SyscallMap["syz_bpf_prog_attach"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	pathStr := []byte(p.BasePath + ".o")
	pathArg := meta.Args[0]
	pathPtr := pathArg.Type.(*PtrType)
	pathBuffer := pathPtr.Elem.(*BufferType)
	pathBufferDir := pathPtr.ElemDir
	pathBufferArg := MakeDataArg(pathBuffer, pathBufferDir, pathStr)
	args[0] = r.allocAddr(s, pathArg.Type, pathArg.Dir(DirIn), pathBufferArg.Size(), pathBufferArg)

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}

func genBpfProgTestRunCall(r *randGen, s *state, p *BpfProg, fd *ResultArg) *Call {
	meta := r.target.SyscallMap["bpf$BPF_PROG_TEST_RUN"]
	args := make([]Arg, len(meta.Args))
	c := MakeCall(meta, nil)

	cmdArg := meta.Args[0]
	args[0], _ = r.generateArg(s, cmdArg.Type, cmdArg.Dir(DirIn))

	testProgArg := meta.Args[1]
	testProgPtr := testProgArg.Type.(*PtrType)
	testProgStruct := testProgPtr.Elem.(*StructType)
	testProgStructDir := testProgPtr.ElemDir

	testProgStructFields := make([]Arg, len(testProgStruct.Fields))
	for i, field := range testProgStruct.Fields {
		if i == 0 {
			resArg := field
			resType := resArg.Type.(*ResourceType)
			testProgStructFields[i] = MakeResultArg(resType, resArg.Dir(DirIn), fd, 0)
		} else {
			testProgStructFields[i], _ = r.generateArg(s, field.Type, field.Dir(DirIn))
		}
	}

	testProgStructArg := MakeGroupArg(testProgStruct, testProgStructDir, testProgStructFields)
	args[1] = r.allocAddr(s, testProgArg.Type, testProgArg.Dir(DirIn), testProgStructArg.Size(), testProgStructArg)

	lenArg := meta.Args[2]
	args[2], _ = r.generateArg(s, lenArg.Type, lenArg.Dir(DirIn))

	c.Args = args
	r.target.assignSizesCall(c)
	return c
}*/

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var errorRegexp = regexp.MustCompile(`(-?\d+) error: (.+)`)

func parseError(line string) (string, string) {
	// 1. rimuovi codici ANSI
	clean := ansiRegexp.ReplaceAllString(line, "")

	// 2. matcha "<numero> error: <messaggio>"
	matches := errorRegexp.FindStringSubmatch(clean)
	if len(matches) < 3 {
		return "", "" // non matcha
	}

	numStr := matches[1]
	msg := matches[2]

	num, err := strconv.Atoi(numStr)
	if err != nil {
		return "", ""
	}

	if num == -1 {
		return msg, "" // usa il messaggio come chiave
	}
	return numStr, msg // usa il numero come chiave
}

func (brf *BpfRuntimeFuzzer) genSeedBpfProg(r *randGen, counts map[string]*ErrorStats, lut map[string]string, activeInjectors []string, maxNumPerErrorType int) *BpfProg {
	var opt BrfGenProgOpt
	var p *BpfProg
	var ok bool

	//	opt.useTestSrc = true
	opt.genProgAttempt = 20
	opt.basePath = brf.workDir

	for i := 0; i < opt.genProgAttempt; i++ {
		fmt.Printf("\tAttempt: %d\n", i+1)
		if p, ok = brf.GenBpfProg(r, opt, ""); !ok {
			continue
		}
		p.FixRef(r)
		p.FixSpinLock(r)

		if err := p.writeCSource(); err != nil {
			fmt.Printf("failed to write bpf program c source: %v\n", err)
			return nil
		}

		/*if err := p.writeGob(); err != nil {
			fmt.Printf("failed to serialize bpf program: %v\n", err)
			return nil
		}*/

		if err := brf.compileBpfProg(p); err != nil {
			if verbose {
				fmt.Printf("failed to compile bpf program: %v\n", err)
			}
			err := os.Remove(p.BasePath + ".c")
			if err != nil {
				return nil
			}
			if verbose {
				fmt.Printf("%s.c removed\n", p.BasePath)
			}

			continue
		}
		r, _ := brf.verifyProg(p)
		//processed keyword also triggers pretty verifier
		if !strings.Contains(string(r), "processed") {

			if verbose {
				fmt.Printf("bpf program not compliant with Pretty Verifier\n")
			}
			err := os.Remove(p.BasePath + ".c")
			if err != nil {
				return nil
			}
			if verbose {
				fmt.Printf("%s.c removed\n", p.BasePath)
			}
			err = os.Remove(p.BasePath + ".o")
			if err != nil {
				return nil
			}
			if verbose {
				fmt.Printf("%s.o removed\n", p.BasePath)
			}

			continue
		}
		key, msg := parseError(string(r))
		if key != "" {
			if _, exists := counts[key]; !exists {
				counts[key] = &ErrorStats{Count: 0, Generators: make(map[string]int)}
			}

			if maxNumPerErrorType > 0 && counts[key].Count > maxNumPerErrorType {
				if verbose || true {
					fmt.Printf("reached limit of program per error\n")
				}
				os.Remove(p.BasePath + ".c")
				os.Remove(p.BasePath + ".o")
				continue
			}

			counts[key].Count++
			// Tracciamo quali injection erano attive per questo errore
			for _, injector := range activeInjectors {
				counts[key].Generators[injector]++
			}

			if _, err := strconv.Atoi(key); err == nil {
				lut[key] = msg
			}
		}
		f, _ := os.Create(p.BasePath + "_output.txt")
		defer f.Close()
		fmt.Fprintf(f, "\n\n%s\n\n", r)
		fmt.Printf("\n%s\n%s\n\n", p.BasePath+".c", r)

		return p
	}
	return nil
}

func (brf *BpfRuntimeFuzzer) mutSeedBpfProg(r *randGen, path string) *BpfProg {
	var opt BrfGenProgOpt
	var p *BpfProg

	//	opt.useTestSrc = true
	opt.genProgAttempt = 20
	opt.basePath = brf.workDir

	p = NewBpfProg(nil, nil, opt, "")
	p.readGob(path)
	p.pt = brf.progTypeMap[p.TypeEnum]

	for i := 0; i < opt.genProgAttempt; i++ {
		for ok := false; !ok; {
			ok = brf.MutBpfProg(r, p, opt)
		}
		p.FixRef(r)
		p.FixSpinLock(r)

		if err := p.writeCSource(); err != nil {
			fmt.Printf("failed to write bpf program c source: %v\n", err)
			return nil
		}

		if err := p.writeGob(); err != nil {
			fmt.Printf("failed to serialize bpf program: %v\n", err)
			return nil
		}

		if err := brf.compileBpfProg(p); err != nil {
			fmt.Printf("failed to compile bpf program: %v\n", err)
			continue
		}

		return p
	}
	return nil
}

func (brf *BpfRuntimeFuzzer) genBpfProg(r *randGen, opt BrfGenProgOpt) (*BpfProg, bool) {
	p := newBpfProg(r, opt)

	return p, true
}

func (brf *BpfRuntimeFuzzer) mutBpfProg(r *randGen, p *BpfProg, opt BrfGenProgOpt) bool {
	return true
}

func (brf *BpfRuntimeFuzzer) compileBpfProg(p *BpfProg) error {
	var timeout time.Duration = 10000000000
	cmd := exec.Command("clang", "-g", "-D__TARGET_ARCH_x86", "-mlittle-endian",
		"-idirafter", "/usr/local/include",
		"-idirafter", "/usr/local/llvm/include",
		"-idirafter", "/usr/include/x86_64-linux-gnu",
		"-idirafter", "/usr/include",
		"-Wno-compare-distinct-pointer-types",
		"-Wno-int-conversion",
		"-O2", "-target", "bpf", "-mcpu=v3",
		"-c", p.BasePath+".c",
		"-o", p.BasePath+".o")
	cmd.Dir = "."
	_, err := osutil.Run(timeout, cmd)
	return err
}

func (brf *BpfRuntimeFuzzer) verifyProg(p *BpfProg) ([]byte, error) {
	var timeout time.Duration = 10000000000
	cmd := exec.Command("./load.sh", p.BasePath+".c")
	cmd.Dir = "."
	return osutil.Run(timeout, cmd)
}

// Ritorna alla logica originale "dumb" random
func selectRandomInjections() []string {
	tmpRand := newRand(rand.NewSource(time.Now().UnixNano()))

	injectNoConstrains = tmpRand.nOutOf(1, 2)
	injectShuffleReturnType = tmpRand.nOutOf(1, 2)
	injectShuffleBoundChecksOperator = tmpRand.nOutOf(1, 2)
	injectOffsetBoundCheck = tmpRand.nOutOf(1, 2)

	// cannot_pass_map_type generation
	injectGetHelperCompactMaps = tmpRand.nOutOf(1, 2)
	injectGetHelperCompatMapTypes = tmpRand.nOutOf(1, 2)
	injectGenerateRemoveFlag = tmpRand.nOutOf(1, 2)

	// very present
	injectGenCompatibleRegTypes = tmpRand.nOutOf(1, 2)
	//injectCompatibleHelpers = tmpRand.nOutOf(1, 2)  //makes the program crash
	injectGenRandBpfHelperCall = tmpRand.nOutOf(1, 2)
	injectGenRandBpfCtxAccess = tmpRand.nOutOf(1, 2)
	injectGenRandReturnVal = tmpRand.nOutOf(1, 2)
	injectFixSpinlock = tmpRand.nOutOf(1, 2)
	injectFixRef = tmpRand.nOutOf(1, 2)

	enabled := []string{}

	if injectNoConstrains {
		enabled = append(enabled, "injectNoConstrains")
	}
	if injectShuffleReturnType {
		enabled = append(enabled, "injectShuffleReturnType")
	}
	if injectShuffleBoundChecksOperator {
		enabled = append(enabled, "injectShuffleBoundChecksOperator")
	}
	if injectOffsetBoundCheck {
		enabled = append(enabled, "injectOffsetBoundCheck")
	}
	if injectGetHelperCompactMaps {
		enabled = append(enabled, "injectGetHelperCompactMaps")
	}
	if injectGetHelperCompatMapTypes {
		enabled = append(enabled, "injectGetHelperCompatMapTypes")
	}
	if injectGenerateRemoveFlag {
		enabled = append(enabled, "injectGenerateRemoveFlag")
	}
	if injectGenCompatibleRegTypes {
		enabled = append(enabled, "injectGenCompatibleRegTypes")
	}
	/*	if injectCompatibleHelpers {	//makes the program crash
		enabled = append(enabled, "injectCompatibleHelpers")
	}*/
	if injectGenRandBpfHelperCall {
		enabled = append(enabled, "injectGenRandBpfHelperCall")
	}
	if injectGenRandBpfCtxAccess {
		enabled = append(enabled, "injectGenRandBpfCtxAccess")
	}
	if injectGenRandReturnVal {
		enabled = append(enabled, "injectGenRandReturnVal")
	}
	if injectFixSpinlock {
		enabled = append(enabled, "injectFixSpinlock")
	}
	if injectFixRef {
		enabled = append(enabled, "injectFixRef")
	}

	return enabled
}

// Nuova funzione con l'euristica, usata solo nella modalità uniform
func selectHeuristicInjections(counts map[string]*ErrorStats) []string {
	tmpRand := newRand(rand.NewSource(time.Now().UnixNano()))

	// Calcola pesi basati sulle performance passate
	weights := make(map[string]int)
	totalErrors := 0
	for _, stat := range counts {
		totalErrors += stat.Count
		for gen, count := range stat.Generators {
			weights[gen] += count
		}
	}

	// Helper per decidere probabilità dinamica
	getProb := func(name string) int {
		base := 50
		if totalErrors == 0 {
			return base // Nessun dato, 50%
		}
		// Se l'injection ha contribuito a errori, aumenta probabilità fino a 90%
		// Se ha contribuito poco, scende verso 10%
		score := weights[name]
		if score == 0 {
			return 20 // Esplorazione minima
		}
		// Normalizza score su totalErrors
		boost := (score * 100) / totalErrors
		if boost > 40 {
			boost = 40
		} // Cap boost
		return base + boost
	}

	injectNoConstrains = tmpRand.nOutOf(getProb("injectNoConstrains"), 100)
	injectShuffleReturnType = tmpRand.nOutOf(getProb("injectShuffleReturnType"), 100)
	injectShuffleBoundChecksOperator = tmpRand.nOutOf(getProb("injectShuffleBoundChecksOperator"), 100)
	injectOffsetBoundCheck = tmpRand.nOutOf(getProb("injectOffsetBoundCheck"), 100)

	// cannot_pass_map_type generation
	injectGetHelperCompactMaps = tmpRand.nOutOf(getProb("injectGetHelperCompactMaps"), 100)
	injectGetHelperCompatMapTypes = tmpRand.nOutOf(getProb("injectGetHelperCompatMapTypes"), 100)
	injectGenerateRemoveFlag = tmpRand.nOutOf(getProb("injectGenerateRemoveFlag"), 100)

	// very present
	injectGenCompatibleRegTypes = tmpRand.nOutOf(getProb("injectGenCompatibleRegTypes"), 100)
	//injectCompatibleHelpers = tmpRand.nOutOf(getProb("injectCompatibleHelpers"), 100)
	injectGenRandBpfHelperCall = tmpRand.nOutOf(getProb("injectGenRandBpfHelperCall"), 100)
	injectGenRandBpfCtxAccess = tmpRand.nOutOf(getProb("injectGenRandBpfCtxAccess"), 100)
	injectGenRandReturnVal = tmpRand.nOutOf(getProb("injectGenRandReturnVal"), 100)
	injectFixSpinlock = tmpRand.nOutOf(getProb("injectFixSpinlock"), 100)
	injectFixRef = tmpRand.nOutOf(getProb("injectFixRef"), 100)

	enabled := []string{}

	if injectNoConstrains {
		enabled = append(enabled, "injectNoConstrains")
	}
	if injectShuffleReturnType {
		enabled = append(enabled, "injectShuffleReturnType")
	}
	if injectShuffleBoundChecksOperator {
		enabled = append(enabled, "injectShuffleBoundChecksOperator")
	}
	if injectOffsetBoundCheck {
		enabled = append(enabled, "injectOffsetBoundCheck")
	}
	if injectGetHelperCompactMaps {
		enabled = append(enabled, "injectGetHelperCompactMaps")
	}
	if injectGetHelperCompatMapTypes {
		enabled = append(enabled, "injectGetHelperCompatMapTypes")
	}
	if injectGenerateRemoveFlag {
		enabled = append(enabled, "injectGenerateRemoveFlag")
	}
	if injectGenCompatibleRegTypes {
		enabled = append(enabled, "injectGenCompatibleRegTypes")
	}
	/*	if injectCompatibleHelpers {	//makes the program crash
		enabled = append(enabled, "injectCompatibleHelpers")
	}*/
	if injectGenRandBpfHelperCall {
		enabled = append(enabled, "injectGenRandBpfHelperCall")
	}
	if injectGenRandBpfCtxAccess {
		enabled = append(enabled, "injectGenRandBpfCtxAccess")
	}
	if injectGenRandReturnVal {
		enabled = append(enabled, "injectGenRandReturnVal")
	}
	if injectFixSpinlock {
		enabled = append(enabled, "injectFixSpinlock")
	}
	if injectFixRef {
		enabled = append(enabled, "injectFixRef")
	}

	return enabled

}

func saveCountsToFile(counts map[string]*ErrorStats, lut map[string]string, filename string) error {
	// 1. Estraggo coppie key:stats
	type kv struct {
		Key   string
		Stats *ErrorStats
	}
	var pairs []kv
	for k, v := range counts {
		pairs = append(pairs, kv{k, v})
	}

	// 2. Ordino per Count decrescente
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Stats.Count > pairs[j].Stats.Count
	})

	// 3. Apro il file
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// 4. Scrivo riga per riga con dettagli injection
	for _, p := range pairs {
		msg := lut[p.Key]
		// Trova injection dominante
		topInj := ""
		topCnt := 0
		for inj, cnt := range p.Stats.Generators {
			if cnt > topCnt {
				topCnt = cnt
				topInj = inj
			}
		}

		_, err := fmt.Fprintf(f, "%s (%s): %d [Top: %s(%d)]\n", msg, p.Key, p.Stats.Count, topInj, topCnt)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {

	verboseFlag := flag.Bool("verbose", false, "enable verbose output")
	mode := flag.String("mode", "standard", "Select mode: standard injection (standard), random injection (random), uniform distribution output (uniform)")
	flag.Parse()
	attempt := 100

	if *verboseFlag {
		verbose = true
		fmt.Println("Verbose mode is ON")
	}
	if *mode == "random" {
		counts := make(map[string]*ErrorStats)
		lut := make(map[string]string)
		for i := 0; i < attempt; i++ {
			fmt.Printf("Generation: %d\n", i+1)
			enabled := selectRandomInjections() // Niente euristiche qui

			brf := NewBpfRuntimeFuzzer(true)
			r := newRand(rand.NewSource(time.Now().UnixNano()))

			brf.genSeedBpfProg(r, counts, lut, enabled, -1)
			err := saveCountsToFile(counts, lut, brf.workDir+"/counts.txt")
			if err != nil {
				return
			}
		}
	} else if *mode == "standard" {
		for f := 0; f < len(injectionFlags); f++ {
			counts := make(map[string]*ErrorStats)
			lut := make(map[string]string)
			*injectionFlags[f] = true

			active := []string{injectionFlagNames[f]}

			for i := 0; i < attempt; i++ {
				fmt.Printf("Generation: %d\n", i+1)

				brf := NewBpfRuntimeFuzzer(true)
				r := newRand(rand.NewSource(time.Now().UnixNano()))

				brf.genSeedBpfProg(r, counts, lut, active, -1)
				err := saveCountsToFile(counts, lut, brf.workDir+"/counts_"+injectionFlagNames[f]+".txt")
				if err != nil {
					return
				}
			}
			*injectionFlags[f] = false

		}

	} else if *mode == "uniform" {
		counts := make(map[string]*ErrorStats)
		lut := make(map[string]string)

		warmUpAttempts := 100

		for f := 0; f < len(injectionFlags); f++ {
			fmt.Printf("Warm-up: Testing injection %s\n", injectionFlagNames[f])
			*injectionFlags[f] = true
			active := []string{injectionFlagNames[f]}

			for k := 0; k < warmUpAttempts; k++ {
				prevTotal := getTotalCount(counts)

				brf := NewBpfRuntimeFuzzer(true)
				r := newRand(rand.NewSource(time.Now().UnixNano()))

				brf.genSeedBpfProg(r, counts, lut, active, 20)

				if getTotalCount(counts) > prevTotal {
					err := saveCountsToFile(counts, lut, brf.workDir+"/counts.txt")
					if err != nil {
						return
					}
				}
			}
			*injectionFlags[f] = false
		}

		for i := 0; !isMapBalanced(counts); i++ {
			fmt.Printf("Generation: %d\n", i+1)

			active := selectHeuristicInjections(counts)

			prevTotal := getTotalCount(counts)

			brf := NewBpfRuntimeFuzzer(true)
			r := newRand(rand.NewSource(time.Now().UnixNano()))

			brf.genSeedBpfProg(r, counts, lut, active, 20)

			if getTotalCount(counts) > prevTotal {
				err := saveCountsToFile(counts, lut, brf.workDir+"/counts.txt")
				if err != nil {
					return
				}
			}
		}
	} else {
		fmt.Println("Unknown mode")
	}

}

func isMapBalanced(m map[string]*ErrorStats) bool {
	max := 0
	min := 100
	for _, v := range m {
		if v.Count > max {
			max = v.Count
		}
		if v.Count < min {
			min = v.Count
		}
	}
	return min == max
}

func getTotalCount(counts map[string]*ErrorStats) int {
	total := 0
	for _, v := range counts {
		total += v.Count
	}
	return total
}
