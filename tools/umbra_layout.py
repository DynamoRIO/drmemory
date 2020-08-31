'''
 **********************************************************
 * Copyright (c) 2020 Google, Inc.  All rights reserved.
 * ********************************************************
'''
'''
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

 * Neither the name of Google, Inc. nor the names of its contributors may be
   used to endorse or promote products derived from this software without
   specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 DAMAGE.
'''
'''
A script used to find Umbra Shadow Memory Layouts.
To format script with yapf: yapf -i --style='{COLUMN_LIMIT: 90}' umbra_layout.py
'''

import sys
import argparse
from enum import Enum
from z3 import *

PTR_SIZE = 64


def get_formatted_hex(integer):
    # Returns a formatted hex string.
    return '0x{0:0{1}X}'.format(integer, 16)


class OS(Enum):
    LINUX = 'linux'
    WINDOWS8 = 'windows8'
    WINDOWS81 = 'windows81'

    def __str__(self):
        return self.value

    def get_app_regions(os):
        # Returns pre-defined app regions of the passed Operating System.
        regions = []
        if os == OS.LINUX:
            regions.append(Region('exec,heap, data', 0x0, 0x10000000000))
            regions.append(Region('pie', 0x550000000000, 0x570000000000))
            regions.append(Region('lib, map, stack, vdso', 0x7F0000000000,
                                  0x800000000000))

            # FIXME: Should we map shadow memory for vsyscall?
            # Doing so can prevent the possibility of a SAT layout.
            #regions.append(Region('vsyscall', 0xFFFFFFFFFF600000, 0xFFFFFFFFFF601000))
        elif os == OS.WINDOWS8:
            regions.append(Region('exec,heap, data', 0x0, 0x1000000000))
            regions.append(Region('lib', 0x7F000000000, 0x80000000000))
        elif os == OS.WINDOWS81:
            regions.append(Region('exec,heap, data', 0x0, 0x30000000000))
            regions.append(Region('lib', 0x7C0000000000, 0x800000000000))
        else:
            sys.exit('Fatal Error: Unknown OS.')

        return regions


class Scale(Enum):
    DOWN_8X = 'down_8x'
    DOWN_4X = 'down_4x'
    DOWN_2X = 'down_2x'
    SAME = 'same'
    UP_2X = 'up_2x'
    UP_4X = 'up_4x'
    UP_8X = 'up_8x'

    def __str__(self):
        return self.value

    def is_scale_up(scale):
        # Returns whether the scale is up or down.
        if (scale == Scale.DOWN_8X):
            return False
        elif (scale == Scale.DOWN_4X):
            return False
        elif (scale == Scale.DOWN_2X):
            return False
        elif (scale == Scale.SAME):
            # We consider SAME as scale up.
            return True
        elif (scale == Scale.UP_2X):
            return True
        elif (scale == Scale.UP_4X):
            return True
        elif (scale == Scale.UP_8X):
            return True
        else:
            sys.exit('Fatal Error: Unknown scale.')

    def get_scale(scale):
        # Returns whether the scale's value.
        if (scale == Scale.DOWN_8X):
            return 3
        elif (scale == Scale.DOWN_4X):
            return 2
        elif (scale == Scale.DOWN_2X):
            return 1
        elif (scale == Scale.SAME):
            return 0
        elif (scale == Scale.UP_2X):
            return 1
        elif (scale == Scale.UP_4X):
            return 2
        elif (scale == Scale.UP_8X):
            return 3
        else:
            sys.exit('Fatal Error: Unknown Scale.')


class Region:
    def __init__(self, desc, start, end):
        # Description of region.
        self.desc = desc
        # Start of region.
        self.start = start
        # End of region.
        self.end = end

    def __str__(self):
        formatted_start = get_formatted_hex(self.start)
        formatted_end = get_formatted_hex(self.end)

        # Return range as a string.
        return '[' + formatted_start + ', ' + formatted_end + ']'

    def __repr__(self):
        return self.__str__()


class RegionExpressionInfo:
    def __init__(self, start_expr, end_expr):
        # Expression of the start of the range.
        self.start_expr = start_expr
        # Expression of the end of the range.
        self.end_expr = end_expr


class Layout:
    def __init__(self, mask, disp, unit, is_scale_up, scale, map_count):
        # Mask used for shadow translation.
        self.mask = mask
        # Displacement used for shadow translation.
        self.disp = disp
        # Size of a unit.
        self.unit = unit
        # Denotes whether the shadow memory is scaled up or down.
        self.is_scale_up = is_scale_up
        # Denotes the scale of shadow memory.
        self.scale = scale
        # The maximum number of multiple maps supported by the layout.
        self.map_count = map_count

    def __translate_boundary(self, addr, map_index):
        # Step 1: mask the app addr.
        masked_addr = (addr & self.mask)

        # Step 2: Derive the unit displacement.
        unit_disp = self.unit * 2 * map_index
        if self.is_scale_up:
            unit_disp = unit_disp >> self.scale
        else:
            unit_disp = unit_disp << self.scale

        # Step 3: Calculate the shadow address
        shdw_addr = masked_addr + self.disp

        # Step 4: Handle special case where top of addr is masked out, e.g., 0x800000000.
        if addr != 0 and shdw_addr == self.disp:
            shdw_addr = shdw_addr + self.mask + 1

        shdw_addr = shdw_addr + unit_disp

        # Step 5: Scale shadow memory.
        if self.is_scale_up:
            return shdw_addr << self.scale
        else:
            return shdw_addr >> self.scale

    def translate(self, region, map_index):
        # Translate the start and end of the passed range for a given map.
        translated_start = self.__translate_boundary(region.start, map_index)
        translated_end = self.__translate_boundary(region.end, map_index)

        # Return a shadow region.
        return Region(None, translated_start, translated_end)

    def __get_translate_expr(addr_expr, disp_var, mask_expr, unit_expr, is_scale_up,
                             scale_expr, map_index_expr):
        # Gets an expression of a translated address.

        # Express address masking.
        masked_addr_expr = simplify(addr_expr & mask_expr)

        # Express unit displacement.
        unit_disp_expr = simplify(unit_expr * BitVecVal(2, PTR_SIZE) * map_index_expr)
        if scale_expr is not None:
            if is_scale_up:
                unit_disp_expr = simplify(LShR(unit_disp_expr, scale_expr))
            else:
                unit_disp_expr = simplify(unit_disp_expr << scale_expr)

        # Express shadow address.
        shdw_addr = simplify(masked_addr_expr + disp_var)

        # Express the special case handling with an ITE expression.
        shdw_addr = simplify(
            If(And(addr_expr != BitVecVal(0, PTR_SIZE), shdw_addr == disp_var),
               shdw_addr + mask_expr + 1, shdw_addr))

        # Add unit displacement.
        shdw_addr = simplify(shdw_addr + unit_disp_expr)

        # Return if scale is N/A.
        if scale_expr is None:
            return shdw_addr

        # Express shadow memory scaling.
        if is_scale_up:
            return simplify(shdw_addr << scale_expr)
        else:
            return simplify(LShR(shdw_addr, scale_expr))

    def get_translate_expr(region_expr_info, disp_var, mask_expr, unit_expr, is_scale_up,
                           scale_expr, map_index_expr):
        # Express translation of start address.
        start_shdw_expr = Layout.__get_translate_expr(region_expr_info.start_expr,
                                                      disp_var, mask_expr, unit_expr,
                                                      is_scale_up, scale_expr,
                                                      map_index_expr)
        # Express translation of end address.
        end_shdw_expr = Layout.__get_translate_expr(region_expr_info.end_expr, disp_var,
                                                    mask_expr, unit_expr, is_scale_up,
                                                    scale_expr, map_index_expr)

        return RegionExpressionInfo(start_shdw_expr, end_shdw_expr)

    def print_layout_info(self):
        print('Memory Layout:')
        print('\tMask:', get_formatted_hex(layout.mask))
        print('\tDisp:', get_formatted_hex(layout.disp))
        print('\tUnit Size:', get_formatted_hex(layout.unit))
        print('\tScale UP:', layout.is_scale_up)
        print('\tScale:', layout.scale)
        print('\n')


def get_translated_regions(layout, regions, map_index):
    # Translate every region in the list and return results in another list.
    return list(map(lambda x: layout.translate(x, map_index), regions))


def print_regions(layout, regions, consider_shadow_of_shadow):

    for map_index in range(layout.map_count):
        translated_regions = get_translated_regions(layout, regions, map_index)
        if consider_shadow_of_shadow:
            translated_again_regions = get_translated_regions(layout, translated_regions,
                                                              map_index)

        print('MAP', map_index)
        for i in range(len(regions)):
            print('\tapp' + str(i) + ':\t', regions[i], ':', regions[i].desc)
            print('\tshd' + str(i) + ':\t', translated_regions[i])

            if consider_shadow_of_shadow:
                print('\tshd\'' + str(i) + ':\t', translated_again_regions[i])

            print('\n')


def check(layout, regions, detect_shadow):
    # Checks for any collisions. If detect_shadow is true, the shadow regions of shadows are also checked.
    # This function does not verify no collisions using constraint solving - see verify() if you want to
    # look at Z3 usage. Instead this function uses 'classical' iteration.
    merged_regions = regions

    for map_index in range(layout.map_count):
        translated_regions = get_translated_regions(layout, regions, map_index)
        # Only check shadow of shadows if flag is set.
        if detect_shadow:
            merged_regions = merged_regions + get_translated_regions(
                layout, translated_regions, map_index)
        merged_regions = merged_regions + translated_regions

    # Sort the list based on the starting address of the range to facilitate collision detection.
    merged_regions.sort(key=lambda x: x.start, reverse=False)

    for i in range(len(merged_regions)):
        cur_region = merged_regions[i]
        if (cur_region.start >= cur_region.end):
            print('Invalid range:', get_formatted_hex(cur_region.start),
                  get_formatted_hex(cur_region.end))
            return False

        if (i == 0):
            continue

        prev_region = merged_regions[i - 1]
        if (cur_region.start < prev_region.end):
            print('Collision:', get_formatted_hex(cur_region.start),
                  get_formatted_hex(prev_region.end))
            return False

    return True


def add_no_collision_constraint(solver, region_expr, region_expr2):
    # Adds a constraint to avoid overlapping regions.
    solver.add(
        Not(
            Or(
                And(ULT(region_expr.start_expr, region_expr2.end_expr),
                    UGT(region_expr.end_expr, region_expr2.start_expr)),
                And(UGT(region_expr.end_expr, region_expr2.start_expr),
                    UGT(region_expr2.end_expr, region_expr.start_expr)))))
    return None


def add_valid_range_constraint(solver, region_expr):
    # A region's start address must be less than its end address.
    solver.add(ULT(region_expr.start_expr, region_expr.end_expr))

    # Pointers must fits within 48-bits. Therefore, we add a constrant that
    # ensures that the top 2 bytes of the region's pointer (be it the start or end)
    # is zero.
    zero_expr = BitVecVal(0, PTR_SIZE)
    high_mask_expr = BitVecVal(0xFFFF000000000000, PTR_SIZE)
    solver.add(region_expr.start_expr & high_mask_expr == zero_expr)
    solver.add(region_expr.end_expr & high_mask_expr == zero_expr)


def verify(mask, disp, max, unit, scale_list, map_count, regions, detect_shadow):
    disp_var = BitVec('d', PTR_SIZE)

    mask_expr = BitVecVal(mask, PTR_SIZE)
    unit_expr = BitVecVal(unit, PTR_SIZE)

    solver = Solver()

    # We constrain the disp value if we are verifying (and not synthesizng).
    if disp is not None:
        solver.add(disp_var == BitVecVal(disp, PTR_SIZE))

    region_exprs = list(
        map(
            lambda x: RegionExpressionInfo(BitVecVal(x.start, PTR_SIZE),
                                           BitVecVal(x.end, PTR_SIZE)), regions))

    # Iterate through each map.
    for map_index in range(map_count):
        map_index_expr = BitVecVal(map_index, PTR_SIZE)

        # Iterate through each scale.
        for scale in scale_list:
            scale_expr = None
            if scale != 0:
                scale_expr = BitVecVal(scale.get_scale(), PTR_SIZE)
            is_scale_up = scale.is_scale_up()

            shdw_exprs = list(
                map(
                    lambda x: Layout.
                    get_translate_expr(x, disp_var, mask_expr, unit_expr, is_scale_up,
                                       scale_expr, map_index_expr), region_exprs))

            # Only consider shadow of shadows if flag is set.
            if detect_shadow:
                shdw_exprs_again = list(
                    map(
                        lambda x: Layout.
                        get_translate_expr(x, disp_var, mask_expr, unit_expr, is_scale_up,
                                           scale_expr, map_index_expr), shdw_exprs))

            # We now start to add constraints.
            for i in range(len(region_exprs)):
                region_expr = region_exprs[i]
                shdw_expr = shdw_exprs[i]

                add_valid_range_constraint(solver, shdw_expr)
                add_no_collision_constraint(solver, region_expr, shdw_expr)

                if detect_shadow:
                    shdw_expr_again = shdw_exprs_again[i]
                    add_valid_range_constraint(solver, shdw_expr_again)
                    add_no_collision_constraint(solver, region_expr, shdw_expr_again)
                    add_no_collision_constraint(solver, shdw_expr, shdw_expr_again)

                for j in range(len(region_exprs)):
                    if (j <= i):
                        continue

                    next_region_expr = region_exprs[j]
                    next_shdw_expr = shdw_exprs[j]

                    add_no_collision_constraint(solver, region_expr, next_shdw_expr)
                    add_no_collision_constraint(solver, shdw_expr, next_region_expr)
                    add_no_collision_constraint(solver, shdw_expr, next_shdw_expr)

                    if detect_shadow:
                        next_shdw_expr_again = shdw_exprs_again[j]
                        add_no_collision_constraint(solver, region_expr,
                                                    next_shdw_expr_again)
                        add_no_collision_constraint(solver, shdw_expr,
                                                    next_shdw_expr_again)
                        add_no_collision_constraint(solver, shdw_expr_again,
                                                    next_region_expr)
                        add_no_collision_constraint(solver, shdw_expr_again,
                                                    next_shdw_expr)
                        add_no_collision_constraint(solver, shdw_expr_again,
                                                    next_shdw_expr_again)

    # The user may specify a max value for the displacement. Add this constraint now.
    if max is not None:
        solver.add(disp_var <= BitVecVal(max, PTR_SIZE))

    # We constrain the disp value to have its lower bytes to zero for easy mapping.
    zero_expr = BitVecVal(0, PTR_SIZE)
    solver.add(UGT(disp_var, zero_expr))
    low_mask_expr = BitVecVal(0xFFFFFFFF, PTR_SIZE)
    solver.add(disp_var & low_mask_expr == zero_expr)

    if solver.check() == sat:
        # If sat, ask the solver to provide as a suitable displacement.
        model = solver.model()
        return model[disp_var].as_long()
    else:
        return None


def parse_scale(scale):
    if (scale == 'all'):
        return list(Scale)
    else:
        return [Scale(scale)]


def print_result(result):
    if result:
        print('SUCCESS\n')
    else:
        print('FAILED\n')


# Set up arg parser.
def set_arg_parser():
    parser = argparse.ArgumentParser(
        description=
        'Facilitates the set up of shadow memory layouts based on direct mappings without collisions. '
        'Mappings are based on known application regions typically set up by the OS. '
        '\n\tSHDW(app) = (app & MASK) + DISP')

    parser.add_argument('--os',
                        type=OS,
                        choices=list(OS),
                        default=OS.LINUX,
                        help='the operating system to consider.')
    parser.add_argument('--mask',
                        type=lambda x: int(x, 0),
                        help='the mask value applied to the app address.')
    parser.add_argument('--disp',
                        type=lambda x: int(x, 0),
                        help='the displacement value used for shadow translation.')
    parser.add_argument('--scale',
                        choices=[
                            'all', Scale.DOWN_8X.value, Scale.DOWN_4X.value,
                            Scale.DOWN_2X.value, Scale.SAME.value, Scale.UP_2X.value,
                            Scale.UP_4X.value, Scale.UP_8X.value
                        ],
                        default='same',
                        help='scale of shadow memory with respect to app memory.')
    parser.add_argument(
        '--verify',
        action='store_true',
        help='verifies whether or not the passed settings result in '
        'a shadow memory layout without any collisions. If no disp value is passed, it will be '
        'synthesized with appropriate values automatically.')
    parser.add_argument(
        '--shadow_collision',
        default=False,
        action='store_true',
        help='Denotes whether to detect collisions with shadow\'s shadow.')
    parser.add_argument('--max',
                        type=lambda x: int(x, 0),
                        help='specifies the max limit of a disp when in find mode.')
    parser.add_argument('--unit',
                        type=lambda x: int(x, 0),
                        default=0x100000000000,
                        help='specifies the size of a unit.')
    parser.add_argument('--count',
                        type=int,
                        default=1,
                        help='specifies the number of maps.')

    return parser


print('*** Umbra Shadow Memory Layout ***\n')

parser = set_arg_parser()
args = parser.parse_args()

print('OS:', args.os.value, '\n')
regions = args.os.get_app_regions()

scale_list = parse_scale(args.scale)

if args.verify:
    disp = verify(args.mask, args.disp, args.max, args.unit, scale_list, args.count,
                  regions, args.shadow_collision)

    # If no disp is returned, then the layout is unsat.
    result = disp is not None
    print_result(result)

    if result:
        for scale in scale_list:
            layout = Layout(args.mask, disp, args.unit, scale.is_scale_up(),
                            scale.get_scale(), args.count)
            layout.print_layout_info()
            print_regions(layout, regions, args.shadow_collision)
else:
    if args.mask is None or args.disp is None:
        sys.exit(
            'Fatal Error: A displacement value needs to be provided as an arguments to check the layout. '
            'Run in Verify Mode if you want to synthesize the value.')

    for scale in scale_list:
        layout = Layout(args.mask, args.disp, args.unit, scale.is_scale_up(),
                        scale.get_scale(), args.count)
        layout.print_layout_info()
        result = check(layout, regions, args.shadow_collision)
        print_result(result)
        print_regions(layout, regions, args.shadow_collision)
