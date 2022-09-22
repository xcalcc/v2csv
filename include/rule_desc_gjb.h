//-*-c++-*-

/*
   Copyright (C) 2019-2022 Xcalibyte (Shenzhen) Limited.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

// ====================================================================
// ====================================================================
//
// Module: rule_desc_std.h
//
// ====================================================================
//


#ifndef RULE_GJB_DESC_H
#define RULE_GJB_DESC_H

typedef enum {
  // new entries must be added at end
  // and also match the struct below
#if 1
#include "GJB5369_enum.inc"
#else
GJB5369 = 500,
G4_1_1_1 = 501,
G4_1_1_2 = 502,
G4_1_1_3 = 503,
G4_1_1_4 = 504,
G4_1_1_5 = 505,
G4_1_1_6 = 506,
G4_1_1_7 = 507,
G4_1_1_8 = 508,
G4_1_1_9 = 509,
G4_1_1_10 = 510,
G4_1_1_11 = 511,
G4_1_1_12 = 512,
G4_1_1_13 = 513,
G4_1_1_14 = 514,
G4_1_1_15 = 515,
G4_1_1_16 = 516,
G4_1_1_17 = 517,
G4_1_1_18 = 518,
G4_1_1_19 = 519,
G4_1_1_20 = 520,
G4_1_1_21 = 521,
G4_1_1_22 = 522,
G4_1_2_1 = 523,
G4_1_2_2 = 524,
G4_1_2_3 = 525,
G4_1_2_4 = 526,
G4_1_2_5 = 527,
G4_1_2_6 = 528,
G4_1_2_7 = 529,
G4_1_2_8 = 530,
G4_1_2_9 = 531,
G4_2_1_1 = 532,
G4_2_1_2 = 533,
G4_2_1_3 = 534,
G4_2_1_4 = 535,
G4_2_1_5 = 536,
G4_2_1_6 = 537,
G4_2_1_7 = 538,
G4_2_1_8 = 539,
G4_2_1_9 = 540,
G4_2_1_10 = 541,
G4_2_2_1 = 542,
G4_2_2_2 = 543,
G4_3_1_1 = 544,
G4_3_1_2 = 545,
G4_3_1_3 = 546,
G4_3_1_4 = 547,
G4_3_1_5 = 548,
G4_3_1_6 = 549,
G4_3_1_7 = 550,
G4_3_1_8 = 551,
G4_G4_1_1 = 552,
G4_G4_1_2 = 553,
G4_G4_1_3 = 554,
G4_G4_2_1 = 555,
G4_G4_2_2 = 556,
G4_5_1_1 = 557,
G4_5_1_2 = 558,
G4_5_2_1 = 559,
G4_6_1_1 = 560,
G4_6_1_2 = 561,
G4_6_1_3 = 562,
G4_6_1_4 = 563,
G4_6_1_5 = 564,
G4_6_1_6 = 565,
G4_6_1_7 = 566,
G4_6_1_8 = 567,
G4_6_1_9 = 568,
G4_6_1_10 = 569,
G4_6_1_11 = 570,
G4_6_1_12 = 571,
G4_6_1_13 = 572,
G4_6_1_14 = 573,
G4_6_1_15 = 574,
G4_6_1_16 = 575,
G4_6_1_17 = 576,
G4_6_1_18 = 577,
G4_6_2_1 = 578,
G4_6_2_2 = 579,
G4_6_2_3 = 580,
G4_6_2_4 = 581,
G4_7_1_1 = 582,
G4_7_1_2 = 583,
G4_7_1_3 = 584,
G4_7_1_4 = 585,
G4_7_1_5 = 586,
G4_7_1_6 = 587,
G4_7_1_7 = 588,
G4_7_1_8 = 589,
G4_7_1_9 = 590,
G4_7_1_10 = 591,
G4_7_2_1 = 592,
G4_7_2_2 = 593,
G4_7_2_3 = 594,
G4_8_1_1 = 595,
G4_8_1_2 = 596,
G4_8_1_3 = 597,
G4_8_2_1 = 598,
G4_8_2_2 = 599,
G4_8_2_3 = 600,
G4_8_2_4 = 601,
G4_8_2_5 = 602,
G4_8_2_6 = 603,
G4_8_2_7 = 604,
G4_8_2_8 = 605,
G4_9_1_1 = 606,
G4_9_1_2 = 607,
G4_9_1_3 = 608,
G4_9_1_4 = 609,
G4_9_1_5 = 610,
G4_10_1_1 = 611,
G4_10_2_1 = 612,
G4_10_2_2 = 613,
G4_11_1_1 = 614,
G4_11_1_2 = 615,
G4_11_2_1 = 616,
G4_11_2_2 = 617,
G4_11_2_3 = 618,
G4_12_1_1 = 619,
G4_12_2_1 = 620,
G4_12_2_2 = 621,
G4_12_2_3 = 622,
G4_13_1_1 = 623,
G4_13_1_2 = 624,
G4_13_1_3 = 625,
G4_13_1_4 = 626,
G4_14_1_1 = 627,
G4_14_1_2 = 628,
G4_14_1_3 = 629,
G4_14_2_1 = 630,
G4_14_2_2 = 631,
G4_15_1_1 = 632,
G4_15_1_2 = 633,
G4_15_1_3 = 634,
G4_15_1_4 = 635,
G4_15_1_5 = 636,
G4_15_1_6 = 637,
G4_15_2_1 = 638,
G4_15_2_2 = 639,
MAX_GJB5369_ENUM = 640,
#endif
  MAX_GJB5369_SZ = MAX_GJB5369_ENUM,
} DFT_GJB_ID;  // unique id for rule

#define DFT_GJB5369_ID DFT_GJB_ID

extern DFT_TYPE defect_gjb5369_vec[]; 

typedef enum {
  // new entries must be added at end
  // and also match the struct below
#if 1
#include "GJB8114_enum.inc"
#else
GJB8114 = 500,
G5_1_1_1 = 501,
G5_1_1_2 = 502,
G5_1_1_3 = 503,
G5_1_1_4 = 504,
G5_1_1_5 = 505,
G5_1_1_6 = 506,
G5_1_1_7 = 507,
G5_1_1_8 = 508,
G5_1_1_9 = 509,
G5_1_1_10 = 510,
G5_1_1_11 = 511,
G5_1_1_12 = 512,
G5_1_1_13 = 513,
G5_1_1_14 = 514,
G5_1_1_15 = 515,
G5_1_1_16 = 516,
G5_1_1_17 = 517,
G5_1_1_18 = 518,
G5_1_1_19 = 519,
G5_1_1_20 = 520,
G5_1_1_21 = 521,
G5_1_1_22 = 522,
G5_1_1_23 = 523,
G5_1_2_1 = 524,
G5_1_2_2 = 525,
G5_1_2_3 = 526,
G5_1_2_4 = 527,
G5_1_2_5 = 528,
G5_1_2_6 = 529,
G5_2_1_1 = 530,
G5_2_1_2 = 531,
G5_2_1_3 = 532,
G5_2_1_4 = 533,
G5_2_1_5 = 534,
G5_2_1_6 = 535,
G5_2_2_1 = 536,
G5_2_2_2 = 537,
G5_2_2_3 = 538,
G5_3_1_1 = 539,
G5_3_1_2 = 540,
G5_3_1_3 = 541,
G5_3_1_4 = 542,
G5_3_1_5 = 543,
G5_3_1_6 = 544,
G5_3_1_7 = 545,
G5_3_1_8 = 546,
G5_3_1_9 = 547,
G5_3_1_10 = 548,
G5_3_2_1 = 549,
G5_3_2_2 = 550,
G5_3_2_3 = 551,
G5_4_1_1 = 552,
G5_4_1_2 = 553,
G5_4_1_3 = 554,
G5_4_1_4 = 555,
G5_4_1_5 = 556,
G5_4_1_6 = 557,
G5_4_1_7 = 558,
G5_4_1_8 = 559,
G5_4_2_1 = 560,
G5_5_1_1 = 561,
G5_5_1_2 = 562,
G5_5_2_1 = 563,
G5_6_1_1 = 564,
G5_6_1_2 = 565,
G5_6_1_3 = 566,
G5_6_1_4 = 567,
G5_6_1_5 = 568,
G5_6_1_6 = 569,
G5_6_1_7 = 570,
G5_6_1_8 = 571,
G5_6_1_9 = 572,
G5_6_1_10 = 573,
G5_6_1_11 = 574,
G5_6_1_12 = 575,
G5_6_1_13 = 576,
G5_6_1_14 = 577,
G5_6_1_15 = 578,
G5_6_1_16 = 579,
G5_6_1_17 = 580,
G5_6_1_18 = 581,
G5_6_1_19 = 582,
G5_6_2_1 = 583,
G5_6_2_2 = 584,
G5_6_2_3 = 585,
G5_6_2_4 = 586,
G5_6_2_5 = 587,
G5_6_2_6 = 588,
G5_7_1_1 = 589,
G5_7_1_2 = 590,
G5_7_1_3 = 591,
G5_7_1_4 = 592,
G5_7_1_5 = 593,
G5_7_1_6 = 594,
G5_7_1_7 = 595,
G5_7_1_8 = 596,
G5_7_1_9 = 597,
G5_7_1_10 = 598,
G5_7_1_11 = 599,
G5_7_1_12 = 600,
G5_7_1_13 = 601,
G5_7_1_14 = 602,
G5_7_1_15 = 603,
G5_7_1_16 = 604,
G5_7_2_1 = 605,
G5_7_2_2 = 606,
G5_7_2_3 = 607,
G5_7_2_4 = 608,
G5_7_2_5 = 609,
G5_8_1_1 = 610,
G5_8_1_2 = 611,
G5_8_1_3 = 612,
G5_8_1_4 = 613,
G5_8_1_5 = 614,
G5_8_2_1 = 615,
G5_8_2_2 = 616,
G5_8_2_3 = 617,
G5_8_2_4 = 618,
G5_9_1_1 = 619,
G5_9_1_2 = 620,
G5_9_1_3 = 621,
G5_9_1_4 = 622,
G5_9_2_1 = 623,
G5_9_2_2 = 624,
G5_9_2_3 = 625,
G5_10_1_1 = 626,
G5_10_1_2 = 627,
G5_10_1_3 = 628,
G5_10_1_4 = 629,
G5_10_1_5 = 630,
G5_10_1_6 = 631,
G5_10_2_1 = 632,
G5_10_2_2 = 633,
G5_10_2_3 = 634,
G5_10_2_4 = 635,
G5_11_1_1 = 636,
G5_11_1_2 = 637,
G5_11_1_3 = 638,
G5_11_1_4 = 639,
G5_11_2_1 = 640,
G5_11_2_2 = 641,
G5_12_1_1 = 642,
G5_12_1_2 = 643,
G5_12_1_3 = 644,
G5_12_1_4 = 645,
G5_12_1_5 = 646,
G5_12_2_1 = 647,
G5_13_1_2 = 648,
G5_13_1_3 = 649,
G5_13_1_4 = 650,
G5_13_1_5 = 651,
G5_13_1_6 = 652,
G5_13_1_7 = 653,
G5_13_1_8 = 654,
G5_13_1_9 = 655,
G5_13_1_10 = 656,
G5_13_1_11 = 657,
G5_13_1_12 = 658,
G5_13_1_13 = 659,
G5_13_1_14 = 660,
G5_13_1_15 = 661,
G5_13_1_16 = 662,
G5_13_2_1 = 663,
G5_13_2_2 = 664,
G6_1_1_1 = 665,
G6_1_1_2 = 666,
G6_1_1_3 = 667,
G6_1_1_4 = 668,
G6_1_2_1 = 669,
G6_1_2_2 = 670,
G6_2_1_1 = 671,
G6_2_1_2 = 672,
G6_2_1_3 = 673,
G6_2_1_4 = 674,
G6_2_1_5 = 675,
G6_3_1_1 = 676,
G6_3_1_2 = 677,
G6_4_1_1 = 678,
G6_4_1_2 = 679,
G6_4_1_3 = 680,
G6_5_1_1 = 681,
G6_5_1_2 = 682,
G6_5_2_1 = 683,
G6_6_1_1 = 684,
G6_6_1_2 = 685,
G6_6_1_3 = 686,
G6_7_1_1 = 687,
G6_7_1_2 = 688,
G6_7_1_3 = 689,
G6_7_2_1 = 690,
G6_7_2_2 = 691,
G6_8_1_1 = 692,
G6_8_1_1 = 693,
G6_8_1_2 = 694,
G6_8_1_3 = 695,
G6_8_1_4 = 696,
G6_8_1_5 = 697,
G6_8_2_1 = 698,
G6_9_1_1 = 699,
G6_9_2_1 = 700,
G6_9_2_2 = 701,
G6_9_2_3 = 702,
G6_9_2_4 = 703,
MAX_GJB8114_ENUM = 704,
#endif
  MAX_GJB8114_SZ = MAX_GJB8114_ENUM,
} DFT_GJB8114_ID;  // unique id for rule

extern DFT_TYPE defect_gjb8114_vec[]; 

#endif // RULE_DESC_GJB_H
