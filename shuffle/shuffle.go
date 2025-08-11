// Package shuffle implements Andrew Neff's verifiable shuffle proof scheme.
// Neff's shuffle proof algorithm as implemented here is described in the paper
// "Verifiable Mixing (Shuffling) of ElGamal Pairs", April 2004.
//
// The PairShuffle type implements the general algorithm
// to prove the correctness of a shuffle of arbitrary ElGamal pairs.
// This will be the primary API of interest for most applications.
// For basic usage, the caller should first instantiate a PairShuffle object,
// then invoke PairShuffle.Init() to initialize the shuffle parameters,
// and finally invoke PairShuffle.Shuffle() to shuffle
// a list of ElGamal pairs, yielding a list of re-randomized pairs
// and a noninteractive proof of its correctness.
//
// The SimpleShuffle type implements Neff's more restrictive "simple shuffle",
// which requires the prover to know the discrete logarithms
// of all the individual ElGamal ciphertexts involved in the shuffle.
// The general PairShuffle builds on this SimpleShuffle scheme,
// but SimpleShuffle may also be used by itself in situations
// that satisfy its assumptions, and is more efficient.
package shuffle

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/proof"                 //零知识证明的库
	sh "go.dedis.ch/kyber/v4/shuffle"
	"go.dedis.ch/kyber/v4/util/random"
)

// Suite wraps the functionalities needed by the shuffle/ package. These are the
// same functionatlities needed by the proof/ package.
type Suite proof.Suite

// XX these could all be inlined into PairShuffleProof; do we want to?

// XX the Zs in front of some field names are a kludge to make them
// accessible via the reflection API,
// which refuses to touch unexported fields in a struct.
//一些字段名称前面的Zs是一个组合，以便通过反射API访问它们，它拒绝访问结构体中未导出的字段。

// P (Prover) step 1: public commitments    //公共承诺
type ega1 struct {
	Gamma            kyber.Point
	A, C, U, W       []kyber.Point
	Lambda1, Lambda2 kyber.Point
}

// V (Verifier) step 2: random challenge t
type ega2 struct {
	Zrho []kyber.Scalar
}

// P step 3: Theta vectors
type ega3 struct {
	D []kyber.Point
}

// V step 4: random challenge c
type ega4 struct {
	Zlambda kyber.Scalar
}

// P step 5: alpha vector
type ega5 struct {
	Zsigma []kyber.Scalar
	Ztau   kyber.Scalar
}

// P and V, step 5: simple k-shuffle proof
type ega6 struct {
	sh.SimpleShuffle
}
//嵌入了另一个结构体

// PairShuffle creates a proof of the correctness of a shuffle
// of a series of ElGamal pairs.
//
// The caller must first invoke Init()
// to establish the cryptographic parameters for the shuffle:
// in particular, the relevant cryptographic Group,
// and the number of ElGamal pairs to be shuffled.
//
// The caller then may either perform its own shuffle,
// according to a permutation of the caller's choosing,
// and invoke Prove() to create a proof of its correctness;
// or alternatively the caller may simply invoke Shuffle()
// to pick a random permutation, compute the shuffle,
// and compute the correctness proof.
type PairShuffle struct {
	grp kyber.Group
	k   int
	p1  ega1
	v2  ega2
	p3  ega3
	v4  ega4
	p5  ega5
	pv6 sh.SimpleShuffle
}

// Init creates a new PairShuffleProof instance for a k-element ElGamal pair shuffle.
// This protocol follows the ElGamal Pair Shuffle defined in section 4 of
// Andrew Neff, "Verifiable Mixing (Shuffling) of ElGamal Pairs", 2004.          //定义点列表的正确长度
func (ps *PairShuffle) Init(grp kyber.Group, k int) *PairShuffle {  
	//kyber.Group 是 go.dedis.ch/kyber/v4 包中的一个接口，代表一个数学群（Group）。数学群在密码学中有广泛的应用，尤其是在公钥密码系统、数字签名和零知识证明中。
	//k是排列的行数
	if k <= 1 {
		panic("can't shuffle permutation of size <= 1")
	}

	// Create a well-formed PairShuffleProof with arrays correctly sized.
	
	//把群环境与规模写入结构体，供后续生成/验证使用。
	ps.grp = grp
	ps.k = k
	
	ps.p1.A = make([]kyber.Point, k)
	ps.p1.C = make([]kyber.Point, k)
	ps.p1.U = make([]kyber.Point, k)
	ps.p1.W = make([]kyber.Point, k)
	ps.v2.Zrho = make([]kyber.Scalar, k)
	ps.p3.D = make([]kyber.Point, k)
	ps.p5.Zsigma = make([]kyber.Scalar, k)
	ps.pv6.Init(grp, k)

	return ps
}

// Prove returns an error if the shuffle is not correct.
func (ps *PairShuffle) Prove(
	pi []int, g, h kyber.Point, beta []kyber.Scalar,
	X, Y []kyber.Point, rand cipher.Stream,
	ctx proof.ProverContext) error {
	/*pi：一个整数数组，表示洗牌的排列。
	g, h：ElGamal 密钥生成的基点。
	beta：一个标量数组，用于洗牌中的随机因子。
	X, Y：原始的 ElGamal 密文对。
	rand：用于生成随机数的随机流。
	ctx：零知识证明上下文，用于存储和传递证明过程中生成的数据。
	*/

	grp := ps.grp
	k := ps.k
	if k != len(pi) || k != len(beta) {
		panic("mismatched vector lengths")
	}

	// Compute pi^-1 inverse permutation
	piinv := make([]int, k)
	for i := 0; i < k; i++ {
		piinv[pi[i]] = i
	}

	// P step 1
	p1 := &ps.p1
	z := grp.Scalar() // scratch

	// pick random secrets
	u := make([]kyber.Scalar, k)
	w := make([]kyber.Scalar, k)
	a := make([]kyber.Scalar, k)
	var tau0, nu, gamma kyber.Scalar
	ctx.PriRand(u, w, a, &tau0, &nu, &gamma)           // PriRand 方法是用来生成随机数并在证明过程中使用。

	// compute public commits
	p1.Gamma = grp.Point().Mul(gamma, g)
	wbeta := grp.Scalar() // scratch
	wbetasum := grp.Scalar().Set(tau0)
	p1.Lambda1 = grp.Point().Null()
	p1.Lambda2 = grp.Point().Null()
	XY := grp.Point()  // scratch
	wu := grp.Scalar() // scratch
	for i := 0; i < k; i++ {
		p1.A[i] = grp.Point().Mul(a[i], g)
		p1.C[i] = grp.Point().Mul(z.Mul(gamma, a[pi[i]]), g)
		p1.U[i] = grp.Point().Mul(u[i], g)
		p1.W[i] = grp.Point().Mul(z.Mul(gamma, w[i]), g)
		wbetasum.Add(wbetasum, wbeta.Mul(w[i], beta[pi[i]]))
		p1.Lambda1.Add(p1.Lambda1, XY.Mul(wu.Sub(w[piinv[i]], u[i]), X[i]))
		p1.Lambda2.Add(p1.Lambda2, XY.Mul(wu.Sub(w[piinv[i]], u[i]), Y[i]))
	}
	p1.Lambda1.Add(p1.Lambda1, XY.Mul(wbetasum, g))
	p1.Lambda2.Add(p1.Lambda2, XY.Mul(wbetasum, h))
	if err := ctx.Put(p1); err != nil {
		//put函数用于将数据存储到一个零知识证明的上下文中.
		return err
	}

	// V step 2
	v2 := &ps.v2
	if err := ctx.PubRand(v2); err != nil {
		return err
	}
	B := make([]kyber.Point, k)
	for i := 0; i < k; i++ {
		P := grp.Point().Mul(v2.Zrho[i], g)
		B[i] = P.Sub(P, p1.U[i])
	}

	// P step 3
	p3 := &ps.p3
	b := make([]kyber.Scalar, k)
	for i := 0; i < k; i++ {
		b[i] = grp.Scalar().Sub(v2.Zrho[i], u[i])
	}
	d := make([]kyber.Scalar, k)
	for i := 0; i < k; i++ {
		d[i] = grp.Scalar().Mul(gamma, b[pi[i]])
		p3.D[i] = grp.Point().Mul(d[i], g)
	}
	if err := ctx.Put(p3); err != nil {
		return err
	}

	// V step 4
	v4 := &ps.v4
	if err := ctx.PubRand(v4); err != nil {
		return err
	}

	// P step 5
	p5 := &ps.p5
	r := make([]kyber.Scalar, k)
	for i := 0; i < k; i++ {
		r[i] = grp.Scalar().Add(a[i], z.Mul(v4.Zlambda, b[i]))
	}
	s := make([]kyber.Scalar, k)
	for i := 0; i < k; i++ {
		s[i] = grp.Scalar().Mul(gamma, r[pi[i]])
	}
	p5.Ztau = grp.Scalar().Neg(tau0)
	for i := 0; i < k; i++ {
		p5.Zsigma[i] = grp.Scalar().Add(w[i], b[pi[i]])
		p5.Ztau.Add(p5.Ztau, z.Mul(b[i], beta[i]))
	}
	if err := ctx.Put(p5); err != nil {
		return err
	}

	// P,V step 6: embedded simple k-shuffle proof
	return ps.pv6.Prove(g, gamma, r, s, rand, ctx)
}

// Verify ElGamal Pair Shuffle proofs.
func (ps *PairShuffle) Verify(
	g, h kyber.Point, X, Y, Xbar, Ybar []kyber.Point,
	ctx proof.VerifierContext) error {

	// Validate all vector lengths
	grp := ps.grp
	k := ps.k
	if len(X) != k || len(Y) != k || len(Xbar) != k || len(Ybar) != k {
		panic("mismatched vector lengths")
	}

	// P step 1
	p1 := &ps.p1
	if err := ctx.Get(p1); err != nil {
		return err
	}

	// V step 2
	v2 := &ps.v2
	if err := ctx.PubRand(v2); err != nil {
		return err
	}
	B := make([]kyber.Point, k)
	for i := 0; i < k; i++ {
		P := grp.Point().Mul(v2.Zrho[i], g)
		B[i] = P.Sub(P, p1.U[i])
	}

	// P step 3
	p3 := &ps.p3
	if err := ctx.Get(p3); err != nil {
		return err
	}

	// V step 4
	v4 := &ps.v4
	if err := ctx.PubRand(v4); err != nil {
		return err
	}

	// P step 5
	p5 := &ps.p5
	if err := ctx.Get(p5); err != nil {
		return err
	}

	// P,V step 6: simple k-shuffle
	if err := ps.pv6.Verify(g, p1.Gamma, ctx); err != nil {
		return err
	}

	// V step 7
	Phi1 := grp.Point().Null()
	Phi2 := grp.Point().Null()
	P := grp.Point() // scratch
	Q := grp.Point() // scratch
	for i := 0; i < k; i++ {
		Phi1 = Phi1.Add(Phi1, P.Mul(p5.Zsigma[i], Xbar[i])) // (31)
		Phi1 = Phi1.Sub(Phi1, P.Mul(v2.Zrho[i], X[i]))
		Phi2 = Phi2.Add(Phi2, P.Mul(p5.Zsigma[i], Ybar[i])) // (32)
		Phi2 = Phi2.Sub(Phi2, P.Mul(v2.Zrho[i], Y[i]))
		//		println("i",i)
		if !P.Mul(p5.Zsigma[i], p1.Gamma).Equal( // (33)
			Q.Add(p1.W[i], p3.D[i])) {
			return errors.New("invalid PairShuffleProof")
		}
	}
	//	println("last")
	//	println("Phi1",Phi1.String());
	//	println("Phi2",Phi2.String());
	//	println("1",P.Add(p1.Lambda1,Q.Mul(g,p5.Ztau)).String());
	//	println("2",P.Add(p1.Lambda2,Q.Mul(h,p5.Ztau)).String());
	if !P.Add(p1.Lambda1, Q.Mul(p5.Ztau, g)).Equal(Phi1) || // (34)
		!P.Add(p1.Lambda2, Q.Mul(p5.Ztau, h)).Equal(Phi2) { // (35)
		return errors.New("invalid PairShuffleProof")
	}

	return nil              //nil是一个预定义的常量，用来表示指针或接口类型的零值。它表示指针不指向任何有效的内存地址，或者接口不包含任何具体的值。
}

// Shuffle randomly shuffles and re-randomizes a set of ElGamal pairs,
// producing a correctness proof in the process.
// Returns (Xbar,Ybar), the shuffled and randomized pairs.
// If g or h is nil, the standard base point is used.
func Shuffle(group kyber.Group, g, h kyber.Point, X, Y []kyber.Point,
	rand cipher.Stream) (XX, YY, Ybaby []kyber.Point, P proof.Prover) {
	/*Shuffle 函数接收一个密码学群 group、两个点 g 和 h（用于ElGamal加密），以及两个切片 X 和 Y 分别存储了ElGamal加密对的明文和密文（两列）部分。rand 是用于生成随机数的密码流。
	返回值包括 XX、YY 和 Ybaby，它们分别是重排后的明文（第一列） Xbar、重排后的密文（第二列） Ybar，以及一个用于生成正确性证明的 proof.Prover 函数。
	*/
	k := len(X)    //把长度赋值给变量 k
	if k != len(Y) {
		panic("X,Y vectors have inconsistent length")
	}

	//初始化一个结构体实例
	ps := PairShuffle{}
	ps.Init(group, k)

	// Pick a random permutation（排列）
	pi := make([]int, k)
	for i := 0; i < k; i++ { // Initialize a trivial permutation (自然数顺序)
		pi[i] = i
	}
	//采用Fisher–Yates shuffle
	for i := k - 1; i > 0; i-- { // Shuffle by random swaps
		j := int(randUint64(rand) % uint64(i+1))
		if j != i {
			t := pi[j]
			pi[j] = pi[i]
			pi[i] = t
		}
	}

	// Pick a fresh ElGamal blinding factor for each pair
	beta := make([]kyber.Scalar, k)
	for i := 0; i < k; i++ {
		beta[i] = ps.grp.Scalar().Pick(rand)
	}

	// Create the output pair vectors
	Xbar := make([]kyber.Point, k)
	Ybar := make([]kyber.Point, k)
	Ytmp := make([]kyber.Point, k)
	for i := 0; i < k; i++ {
		Xbar[i] = ps.grp.Point().Mul(beta[pi[i]], g)
		Xbar[i].Add(Xbar[i], X[pi[i]])
		Ytmp[i] = ps.grp.Point().Mul(beta[pi[i]], h)
		Ybar[i] = ps.grp.Point().Mul(beta[pi[i]], h)
		Ybar[i].Add(Ybar[i], Y[pi[i]])
	}
	/*创建一个长度为 k 的 beta 数组，每个元素是一个随机的密码学标量。然后对每个加密对 (X[i], Y[i]) 进行ElGamal再随机化：
	计算 Xbar[i] = beta[pi[i]] * g + X[pi[i]]
	计算 Ybar[i] = beta[pi[i]] * h + Y[pi[i]]
	同时，将 Ybar[i] 的临时值存储在 Ytmp[i] 中，这些临时值将在后面的证明中使用。
	*/

	//这里不直接生成证明材料，外部框架调用它时，再把 pi, g, h, beta, X, Y 这些秘密/中间量带入，按协议和挑战生成零知识
	prover := func(ctx proof.ProverContext) error {
		return ps.Prove(pi, g, h, beta, X, Y, rand, ctx)
	}
	return Xbar, Ybar, Ytmp, prover
}

// randUint64 chooses a uniform random uint64
func randUint64(rand cipher.Stream) uint64 {
	//rand cipher.Stream用于生成随机比特流。在 Go 语言中，cipher.Stream 是一个接口，它定义了一种生成伪随机数流的方式。
	b := random.Bits(64, false, rand)
	/*random.Bits(64, false, rand): 这一行调用了 random 包中的 Bits 函数。它接受三个参数：
	64: 表示要生成的比特数，即64位。
	false: 表示生成的比特流是否应为随机化的。在这里，它设置为 false，表示生成真正的随机比特流。
	rand: 是用于生成比特流的随机数流接口。
	random.Bits 函数将返回一个长度为64的 byte 数组 b，其中包含随机生成的比特。
	*/
	return binary.BigEndian.Uint64(b)
	//binary.BigEndian.Uint64 函数将一个长度为8的 byte 数组解释为一个大端序（BigEndian）的 uint64 整数。
	//大端序（Big Endian）是一种字节序的表示方式，它规定数据的高字节存储在内存的低地址端，低字节存储在内存的高地址端。
}

// Verifier produces a Sigma-protocol verifier to check the correctness of a shuffle.
func Verifier(group kyber.Group, g, h kyber.Point,
	X, Y, Xbar, Ybar []kyber.Point) proof.Verifier {

	ps := PairShuffle{}
	ps.Init(group, len(X))
	verifier := func(ctx proof.VerifierContext) error {
		return ps.Verify(g, h, X, Y, Xbar, Ybar, ctx)
	}
	//创建一个验证者函数，通过定义一个匿名函数，调用Verify函数实现。
	return verifier
}
