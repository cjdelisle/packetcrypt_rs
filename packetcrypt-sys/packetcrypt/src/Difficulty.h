/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef DifficultyTest_H
#define DifficultyTest_H

#include <stdint.h>
#include <stdbool.h>

bool pc_is_min_ann_diff_ok(uint32_t ann_tar);
uint32_t pc_degrade_announcement_target(uint32_t ann_tar, uint32_t ann_age_blocks);
uint64_t pc_get_hashrate_multiplier(uint32_t ann_tar, uint64_t ann_count);
uint32_t pc_get_effective_target(uint32_t block_tar, uint32_t ann_tar, uint64_t ann_count);

static inline uint32_t Difficulty_getEffectiveTarget(uint32_t blockTar, uint32_t annTar, uint64_t annCount)
{
    return pc_get_effective_target(blockTar, annTar, annCount);
}

static inline uint32_t Difficulty_degradeAnnouncementTarget(uint32_t annTar, uint32_t annAgeBlocks)
{
    return pc_degrade_announcement_target(annTar, annAgeBlocks);
}

static inline bool Difficulty_isMinAnnDiffOk(uint32_t target)
{
    return pc_is_min_ann_diff_ok(target);
}

static inline uint64_t Difficulty_getHashRateMultiplier(uint32_t annTar, uint64_t annCount)
{
    return pc_get_hashrate_multiplier(annTar, annCount);
}

#endif
