#define MNT_LOCAL 0x00001000
#define MNT_IGNORE_OWNERSHIP 0x00200000
static int admissible(unsigned int flags){return (flags & MNT_LOCAL)!=0 && (flags & MNT_IGNORE_OWNERS)==0;}
int main(void){return (!admissible(MNT_LOCAL) || admissible(0) || admissible(MNT_LOCAL|MNT_IGNORE_OWNERSHIP) || admissible(MNT_IGNORE_OWNERSHIP));}
