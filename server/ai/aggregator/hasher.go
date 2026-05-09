package aggregator

import (
	"hash"
	"strings"
	"unicode"
)

// SimHash 计算文本的 SimHash 值
// 使用 64 位 SimHash 算法，对文本进行分词、哈希、累加
func SimHash(text string) uint64 {
	// 标准化文本：转小写、去除标点
	normalized := normalizeText(text)

	// 分词
	words := strings.Fields(normalized)
	if len(words) == 0 {
		return 0
	}

	// 初始化 64 位向量
	var v [64]int

	// 对每个词计算哈希并累加到向量
	for _, word := range words {
		h := hashWord(word)
		for i := 0; i < 64; i++ {
			bit := (h >> i) & 1
			if bit == 1 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}

	// 转换为 64 位哈希值
	var simHash uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			simHash |= (1 << i)
		}
	}

	return simHash
}

// normalizeText 标准化文本
func normalizeText(text string) string {
	return strings.ToLower(text)
}

// hashWord 计算词的哈希值（使用 64 位 FNV-1a）
func hashWord(word string) uint64 {
	var h uint64 = 14695981039346656037 // FNV offset basis
	for _, c := range word {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			h ^= uint64(unicode.ToLower(c))
			h *= 1099511628211 // FNV prime
		}
	}
	return h
}

// hashFallback 使用 hash.Hash 计算哈希
func hashFallback(word string, writer hash.Hash64) uint64 {
	writer.Reset()
	writer.Write([]byte(word))
	return writer.Sum64()
}

// HammingDistance 计算两个 SimHash 的汉明距离
func HammingDistance(h1, h2 uint64) int {
	xor := h1 ^ h2
	distance := 0
	for xor != 0 {
		distance++
		xor &= xor - 1
	}
	return distance
}

// IsSimilar 检查两个文本是否相似（汉明距离 < k）
// k: 最大允许的汉明距离阈值
func IsSimilar(text1, text2 string, k int) bool {
	h1 := SimHash(text1)
	h2 := SimHash(text2)
	return HammingDistance(h1, h2) < k
}

// GetSimilarity 计算两个 SimHash 的相似度（1 - hammingDistance/64）
func GetSimilarity(h1, h2 uint64) float64 {
	dist := HammingDistance(h1, h2)
	return 1.0 - float64(dist)/64.0
}
