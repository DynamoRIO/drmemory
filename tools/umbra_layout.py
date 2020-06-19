import argparse
from z3 import *

PTR_SIZE = 64

def get_formatted_hex(integer):
    # Returns a formatted hex string.
    return '0x{0:0{1}X}'.format(integer, 16)


class Region:
    def __init__(self, desc, start, end):
        # Description of region
        self.desc = desc
        # Start of region
        self.start = start
        # End of region
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
        shdw_addr = masked_addr + self.disp + unit_disp

        # Step 4: Handle special case where top of addr is masked out, e.g., 0x800000000.
        if addr != 0 and shdw_addr == self.disp:
            shdw_addr = shdw_addr + self.mask + 1

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

    def __get_translate_expr(addr_expr, disp_var, mask_expr, unit_expr, is_scale_up, scale_expr, map_index_expr):
        # Gets an expression of a translated address.

        # Express address masking.
        masked_addr_expr = simplify(addr_expr & mask_expr)

        # Express unit displacement.
        unit_disp_expr = simplify(unit_expr * BitVecVal(2, PTR_SIZE) * map_index_expr)
        if scale is not None:
            if is_scale_up:
                unit_disp_expr = simplify(LShR(unit_disp_expr, scale))
            else:
                unit_disp_expr = simplify(unit_disp_expr << scale)

        # Express shadow address.
        shdw_addr = masked_addr_expr + disp_var + unit_disp_expr

        # Express the special case handling with an ITE expression.
        shdw_addr = simplify(If(And(addr_expr != BitVecVal(0, PTR_SIZE), shdw_addr == disp_var), shdw_addr + mask_expr + 1, shdw_addr))

        # Return if scale is N\A.
        if scale is None:
            return shdw_addr

        # Express shadow memory scaling.
        if is_scale_up:
            return simplify(shdw_addr << scale)
        else:
            return simplify(LShR(shdw_addr, scale))

    def get_translate_expr(region_expr_info, disp_var, mask_expr, unit_expr, is_scale_up, scale_expr, map_index_expr):
        # Express translation of start address.
        start_shdw_expr = Layout.__get_translate_expr(
            region_expr_info.start_expr, disp_var, mask_expr, unit_expr, is_scale_up, scale_expr, map_index_expr)
        # Express translation of end address.
        end_shdw_expr = Layout.__get_translate_expr(
            region_expr_info.end_expr, disp_var, mask_expr, unit_expr, is_scale_up, scale_expr, map_index_expr)

        return RegionExpressionInfo(start_shdw_expr, end_shdw_expr)

def get_linux_app_regions():
    # Define app regions on Linux.
    regions = []
    regions.append(Region('exec,heap, data', 0x0, 0x10000000000))
    regions.append(Region('pie', 0x550000000000, 0x570000000000))
    regions.append(Region('lib, map, stack, vdso', 0x7F0000000000, 0x800000000000))

    # FIXME: Should we map shadow memory for vsyscall? Doing so can prevent the possibility of a SAT layout.
    #regions.append(Region('vsyscall', 0xFFFFFFFFFF600000, 0xFFFFFFFFFF601000))

    return regions

def get_windows8_app_regions():
    # Define app regions on Windows 8.
    regions = []
    regions.append(Region('exec,heap, data', 0x0, 0x1000000000))
    regions.append(Region('lib', 0x7F000000000, 0x80000000000))

    return regions

def get_windows81_app_regions():
    # Define app regions on Windows 8.1
    regions = []
    regions.append(Region('exec,heap, data', 0x0, 0x30000000000))
    regions.append(Region('lib', 0x7C0000000000, 0x800000000000))

    return regions

def get_translated_regions(layout, regions, map_index):
    # Translate every region in the list and return results in another list
    return list(map(lambda x: layout.translate(x, map_index), regions))

def print_regions(layout, regions, consider_shadow_of_shadow):
    print('Memory Layout:\n')
    print('\tDisp:', get_formatted_hex(layout.disp))
    print('\tMask:', get_formatted_hex(layout.mask))
    print('\tUnit Size:', get_formatted_hex(layout.unit))
    print('\tScale:', layout.scale)
    print('\tMap Count:', layout.map_count, '\n')

    for map_index in range(layout.map_count):
        translated_regions = get_translated_regions(layout, regions, map_index)
        if consider_shadow_of_shadow:
            translated_again_regions = get_translated_regions(layout, translated_regions, map_index)

        print('MAP', map_index)
        for i in range(len(regions)):
            print('\tapp' + str(i) + ':\t', regions[i], ':', regions[i].desc)
            print('\tshd' + str(i) + ':\t', translated_regions[i])

            if consider_shadow_of_shadow:
                print('\tshd\'' + str(i) + ':\t', translated_again_regions[i])

            print('\n')


def detect_collisions(merged_regions):
    merged_regions.sort(key=lambda x: x.start, reverse=False)

    for i in range(len(merged_regions)):
        cur_region = merged_regions[i]

        if (cur_region.start >= cur_region.end):
            print('Invalid range:', get_formatted_hex(cur_region.start), get_formatted_hex(cur_region.end))
            return True

        if (i == 0):
            continue

        prev_region = merged_regions[i-1]

        if (cur_region.start < prev_region.end):
            print('Collision:', get_formatted_hex(cur_region.start), get_formatted_hex(prev_region.end))
            return True

    return False


def check(layout, regions, detect_shadow):
    merged_regions = regions
    for map_index in range(layout.map_count):
        translated_regions =  get_translated_regions(layout, regions, map_index)
        if detect_shadow:
            merged_regions = merged_regions + get_translated_regions(layout, translated_regions, map_index)
        merged_regions = merged_regions + translated_regions

    if(detect_collisions(merged_regions)):
        print('Result: FAILED\n')
    else:
        print('Result: SUCCESS\n')

    print_regions(layout, regions, detect_shadow)


def add_no_collision_constraint(solver, region_expr, region_expr2):
    solver.add(Not(Or(
        And(ULT(region_expr.start_expr, region_expr2.end_expr),
            UGT(region_expr.end_expr, region_expr2.start_expr)),
        And(UGT(region_expr.end_expr, region_expr2.start_expr), UGT(region_expr2.end_expr, region_expr.start_expr)))
    ))
    return None

def add_valid_range_constraint(solver, region_expr):
    solver.add(ULT(region_expr.start_expr, region_expr.end_expr))

    zero_expr = BitVecVal(0, PTR_SIZE)
    high_mask_expr = BitVecVal(0xFFFF000000000000, PTR_SIZE)
    solver.add(region_expr.start_expr & high_mask_expr == zero_expr)
    solver.add(region_expr.end_expr & high_mask_expr == zero_expr)


def verify(mask, disp,  max, unit, is_scale_up, scale, map_count, regions, detect_shadow):
    disp_var = BitVec('d', PTR_SIZE)
    mask_expr = BitVecVal(mask, PTR_SIZE)
    unit_expr = BitVecVal(unit, PTR_SIZE)

    scale_expr = None
    if scale != 0:
        scale_expr = BitVecVal(scale, PTR_SIZE)

    # Only consider one map to keep constraints small.
    map_index_expr = BitVecVal(0, PTR_SIZE)

    solver = Solver()

    if disp is not None:
        solver.add(disp_var == BitVecVal(disp, PTR_SIZE))

    region_exprs = list(
        map(lambda x: RegionExpressionInfo(BitVecVal(x.start, PTR_SIZE), BitVecVal(x.end, PTR_SIZE)), regions))
    shdw_exprs = list(
        map(lambda x: Layout.get_translate_expr(x, disp_var, mask_expr, unit_expr, is_scale_up, scale_expr, map_index_expr), region_exprs))

    if detect_shadow:
        shdw_exprs_again = list(
            map(lambda x: Layout.get_translate_expr(x, disp_var, mask_expr, unit_expr, is_scale_up, scale_expr, map_index_expr), shdw_exprs))

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
                add_no_collision_constraint(solver, region_expr, next_shdw_expr_again)
                add_no_collision_constraint(solver, shdw_expr, next_shdw_expr_again)
                add_no_collision_constraint(solver, shdw_expr_again, next_region_expr)
                add_no_collision_constraint(solver, shdw_expr_again, next_shdw_expr)
                add_no_collision_constraint(solver, shdw_expr_again, next_shdw_expr_again)

    if max is not None:
        solver.add(disp_var <= BitVecVal(max, PTR_SIZE))

    zero_expr = BitVecVal(0, PTR_SIZE)
    solver.add(UGT(disp_var, zero_expr))
    low_mask_expr = BitVecVal(0xFFFFFFFF, PTR_SIZE)
    solver.add(disp_var & low_mask_expr == zero_expr)

    if solver.check() == sat:
        model = solver.model()
        disp_result = model[disp_var].as_long()
        print('Result: SUCCESS\n')
        return disp_result
    else:
        print('Result: FAILED\n')
        return None

# Parse OS arg provided by the user.
def parse_os(choice):
    if (choice == 'linux'):
        return get_linux_app_regions()
    elif choice == 'windows8':
        return get_windows8_app_regions()
    elif choice == 'windows81':
        return get_windows81_app_regions()
    else:
        sys.exit('Fatal Error: Bad OS choice')

# Parse Scale arg provided by the user.
def parse_scale(choice):
    if (choice == 'down_8x'):
        return False, 3
    elif (choice == 'down_4x'):
        return False, 2
    elif (choice == 'down_2x'):
        return False, 1
    elif (choice == 'same'):
        return True, 0
    elif (choice == 'up_2x'):
        return True, 1
    elif (choice == 'up_4x'):
        return True, 2
    elif (choice == 'up_8x'):
        return True, 3
    else:
        sys.exit('Fatal Error: Bad scale choice.')

parser = argparse.ArgumentParser(
    description='Facilitates the set up of shadow memory layouts based on direct mappings.'
                 'Mappings are based on known Application Regions typically set up by the OS.'
                 '\n\tSHDW(app) = (app & MASK) + DISP')
parser.add_argument('--os', choices=['linux', 'windows8', 'windows81'],
                    default='linux', help='the operating system to consider.')
parser.add_argument('--mask', type=lambda x: int(x, 0),
                    help='the mask value applied to the app address.')
parser.add_argument('--disp', type=lambda x: int(x, 0),
                    help='the displacement value used for shadow translation.')
parser.add_argument('--scale', choices=['down_8x', 'down_4x', 'down_2x', 'same', 'up_2x', 'up_4x', 'up_8x'],
                    default='same', help='scale of shadow memory with respect to app memory.')
parser.add_argument('--verify', action='store_true', help='verifies whether or not the passed  value results in'
                    'a shadow memory layout without any collisions. If no disp or mask values are passed, they will be'
                    'synthesized with appropriate values automatically. Current implementation does not check for'
                    'multiple maps.')
parser.add_argument('--shadow_collision', default=False, action='store_true', help='Denotes whether to detect collisions with shadow\'s shadow.')
parser.add_argument('--max', type=lambda x: int(x, 0),
                    help='specifies the max limit of a disp when in find mode.')
parser.add_argument('--unit', type=lambda x: int(x, 0),
                    default=0x100000000000, help='specifies the size of a unit.')
parser.add_argument('--count', type=int, default=1, help='specifies the number of maps.')

args = parser.parse_args()

print('*** Umbra Shadow Memory Layout ***\n')
print('OS:', args.os, '\n')

regions = parse_os(args.os)

is_scale_up, scale = parse_scale(args.scale)

if args.verify:
    disp = verify(args.mask, args.disp, args.max, args.unit, is_scale_up, scale, args.count, regions, args.shadow_collision)
    if (disp is not None):
        layout = Layout(args.mask, disp, args.unit, is_scale_up, scale, args.count)
        print_regions(layout, regions, args.shadow_collision)
else:
    if args.mask is None or args.disp is None:
        sys.exit('Fatal Error: A displacement value needs to be provided as an arguments to check the layout. Run in Verify Mode if you want to synthesize the value')

    if args.count > 1:
        print('Warning: Can only verify for one map.')
    layout = Layout(args.mask, args.disp, args.unit, is_scale_up, scale, 1)
    check(layout, regions, args.shadow_collision)
