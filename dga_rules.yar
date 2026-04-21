rule dga_zodiac {
    meta:
        description = "Uses zodiac sign derived from a random day+month combo as input to UUID5 → SHA-256 → character substitution."
        dga_type    = "zodiac"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[b|c|d|e|f|h|k|m|n|o|p|q|r|w|x]+|[0|1|2|3|4|5|6|7|8|9]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_time_based {
    meta:
        description = "Formats a date offset from today and uses it as the domain body."
        dga_type    = "time_based"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[0|1|2|3|4|5|6|7|8|9]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_seed_based {
    meta:
        description = "MD5 of a seed string, truncated and updated iteratively for each domain."
        dga_type    = "seed_based"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f]+|[0|1|2|3|4|5|6|7|8|9]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_dictionary {
    meta:
        description = "Concatenates random characters from a custom dictionary until the desired length is reached."
        dga_type    = "dictionary"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_prng {
    meta:
        description = "Seeds Python's random module and generates character streams."
        dga_type    = "prng"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z]+|[0|1|2|3|4|5|6|7|8|9]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_arithmetic {
    meta:
        description = "Adds a random value to the seed each iteration and converts the result to a string."
        dga_type    = "arithmetic"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[0|1|2|3|4|5|6|7|8|9]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_permutation {
    meta:
        description = "Generates all permutations of a base domain's characters and rotates through them."
        dga_type    = "permutation"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|e|l|m|p|x]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_fibonacci {
    meta:
        description = "Uses Fibonacci numbers as character indices into the alphabet."
        dga_type    = "fibonacci"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[W|X|a|b|c|d|f|i|k|l|m|n|t|v|x|z]+|[6|7|8]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_base32_base64 {
    meta:
        description = "Base32 or Base64 encodes the seed and uses the output as the domain body."
        dga_type    = "base32_base64"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f|g|i|j|k|l|m|n|o|q|r|t|u|v|w|x|y|z]+|[0|1|2|3|4|5]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_wordlist {
    meta:
        description = "Concatenates two random words from a hardcoded list (like the Crowdstrike variant)."
        dga_type    = "wordlist"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_vowel_consonant {
    meta:
        description = "Alternates vowels and consonants to produce pronounceable gibberish."
        dga_type    = "vowel_consonant"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_morse_code {
    meta:
        description = "Converts random letters to Morse code dot/dash sequences, mapped to 'o'/'e' chars."
        dga_type    = "morse_code"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[e|o]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_emoji {
    meta:
        description = "Uses emoji Unicode codepoints as the domain body (internationalized domains)."
        dga_type    = "emoji"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|g|h|i|k|l|m|n|o|p|r|s|t|u|y]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_coordinate {
    meta:
        description = "Converts random GPS coordinates to decimal strings used as domain names."
        dga_type    = "coordinate"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[0|1|2|3|4|5|6|7|8|9]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_musical_notes {
    meta:
        description = "Concatenates note+octave pairs (e.g. 'A3B2C4') as the domain body."
        dga_type    = "musical_notes"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f|g]+|[1|2|3|4|5]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_ranbyus {
    meta:
        description = "Banking trojan DGA using 14-iteration LFSR bitwise mutation on day/year/seed integers. Real Ranbyus algorithm."
        dga_type    = "ranbyus"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_dyre {
    meta:
        description = "Banking trojan DGA. Date → MD5 hex seed → random.seed() → 1000-5000 domains/day. Real Dyre algorithm."
        dga_type    = "dyre"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_dword_hex {
    meta:
        description = "Random 32-bit unsigned integer converted to its 8-char hexadecimal representation (Cybereason variant)."
        dga_type    = "dword_hex"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f]+|[0|1|2|3|4|5|6|7|8|9]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_punycode_like {
    meta:
        description = "Generates XN--<random>-<constant suffix> format domains that look like internationalised names (Cybereason variant)."
        dga_type    = "punycode_like"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[w]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_word_prefix {
    meta:
        description = "Constant English word prefix ('five', 'pop') + sequential number + random suffix. Cybereason Russian variant."
        dga_type    = "word_prefix"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z]+|[0|1|2|3|4|5|6|7|8|9]+{1,3}/ nocase
    condition:
        $dga_pattern
}

rule dga_ddns_subdomain {
    meta:
        description = "DGA type: ddns_subdomain"
        dga_type    = "ddns_subdomain"
        author      = "Angelware AUA Lab"
        date        = "2026-04-21"
    strings:
        $dga_pattern = /[a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z]+|[0|1|2|3|4|5|6|7|8|9]+{1,3}/ nocase
    condition:
        $dga_pattern
}
