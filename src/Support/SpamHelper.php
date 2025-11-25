<?php

namespace App\Support;

class SpamHelper
{
    public static function shannonEntropy(string $string): float
    {
        $len = strlen($string);
        if ($len === 0) {
            return 0.0;
        }

        $freq = array_count_values(str_split($string));

        $entropy = 0.0;

        foreach ($freq as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }

    public static function randomTokenScore(string $token): float
    {
        $len = strlen($token);
        if ($len < 8) {
            return 0.0;
        }

        if (preg_match('/^[A-Za-z0-9]+$/', $token) !== 1) {
            return 0.0;
        }

        $hasUpper = preg_match('/[A-Z]/', $token) === 1;
        $hasLower = preg_match('/[a-z]/', $token) === 1;

        $lengthScore = max(0.0, min(1.0, ($len - 7) / 8));

        $entropy = self::shannonEntropy($token);
        $entropyScore = max(0.0, min(1.0, $entropy - 3.5));

        $mixedCaseScore = ($hasUpper && $hasLower) ? 1.0 : 0.0;

        $vowelCount = preg_match_all('/[aeiou]/i', $token) ?: 0;
        $vowelRatio = $vowelCount / $len;
        $vowelScore = $vowelRatio < 0.30
            ? max(0.0, min(1.0, (0.30 - $vowelRatio) / 0.30))
            : 0.0;

        $scores = [$lengthScore, $entropyScore, $mixedCaseScore, $vowelScore];

        $sum = array_sum($scores);

        return $sum > 0.0 ? $sum / count($scores) : 0.0;
    }

    public static function spamRandomStringScore(string $text): float
    {
        $tokens = preg_split('/[^A-Za-z0-9]+/', $text, -1, PREG_SPLIT_NO_EMPTY);
        if (!$tokens) {
            return 0.0;
        }

        $total = count($tokens);
        $maxTokenScore = 0.0;
        $suspicious = 0;

        foreach ($tokens as $token) {
            $score = self::randomTokenScore($token);

            if ($score > $maxTokenScore) {
                $maxTokenScore = $score;
            }

            if ($score >= 0.6) {
                $suspicious++;
            }
        }

        $ratio = $suspicious / $total;

        return ($maxTokenScore * 0.7) + ($ratio * 0.3);
    }
}