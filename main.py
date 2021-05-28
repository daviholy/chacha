# coding=utf-8
import numpy as np
import sys
import secrets
import base64
import time
import math

ROUNDS = 10

def genKey() -> bytes:
    """generate random 256-bit long key in ascii85"""
    tmp = np.empty(4)
    for i in range(4):
        tmp[i] = secrets.randbits(64)
    return (base64.a85encode(tmp))


def genNonce() -> np.uint32:
    """generate 96bit nonce"""
    return [np.uint32(secrets.randbits(32)) for _ in range(3)]


def genKeyBlock(key: np.uint32, nonce: np.uint32, counter: np.uint32) -> np.uint32:
    """generate 512-bit block for the specified segment"""

    def QR(a: np.uint32, b: np.uint32, c: np.uint32, d: np.uint32) -> None:
        """chachas quarter round function"""
        a += b
        d = np.bitwise_xor(a, d)
        d = lR(d, 16)
        c += d
        b = np.bitwise_xor(b, c)
        b = lR(b, 12)
        a += b
        d = np.bitwise_xor(d, a)
        d = lR(d, 8)
        c += d
        b = np.bitwise_xor(b, c)
        b = lR(b, 7)
        return (a, b, c, d)

    block = np.uint32([0x65787061, 0x6e642033, 0x322d6279, 0x7465206b,  # "expand 32-byte k" constant
                       key[0], key[1], key[2], key[3],
                       key[4], key[5], key[6], key[7],
                       nonce[0], nonce[1], nonce[2], counter])
    for _ in range(ROUNDS):
        # odd round
        block[0], block[4], block[8], block[12] = QR(
            block[0], block[4], block[8], block[12])  # column 1
        block[1], block[5], block[9], block[13] = QR(
            block[1], block[5], block[9], block[13])  # column 2
        block[2], block[6], block[10], block[14] = QR(
            block[2], block[6], block[10], block[14])  # column 3
        block[3], block[7], block[11], block[15] = QR(
            block[3], block[7], block[11], block[15])  # column 4
        # even round - diagonals starting from main and then going up
        block[0], block[5], block[10], block[15] = QR(
            block[0], block[5], block[10], block[15])
        block[1], block[6], block[11], block[12] = QR(
            block[1], block[6], block[11], block[12])
        block[2], block[7], block[8], block[13] = QR(
            block[2], block[7], block[8], block[13])
        block[3], block[4], block[9], block[14] = QR(
            block[3], block[4], block[9], block[14])
    return (block)


def decodekey(key: bytes) -> bytes:
    """decode the key encoded in ascii85"""
    return (base64.a85decode(key))


def lR(n: np.int64, d: np.int64) -> np.uint32:
    """left rotation of int32"""
    return(n << d) | (n >> (32-d))


def rR(n: np.int64, d: np.int64) -> np.uint32:
    """right rotation of int32"""
    return(n >> d) | (n << (32-d))


if __name__ == "__main__":
    start = time.perf_counter()
    nonce = genNonce()
    key = np.frombuffer(decodekey(genKey()), np.uint8)
    secret = np.frombuffer(
        u"""„Tak nám zabili Ferdinanda,” řekla posluhovačka panu Švejkovi, který opustiv před léty vojenskou službu, když byl definitivně prohlášen vojenskou lékařskou komisí za blba, živil se prodejem psů, ošklivých nečistokrevných oblud, kterým padělal rodokmeny.
Kromě tohoto zaměstnání byl stižen revmatismem a mazal si právě kolena opodeldokem.
„Kerýho Ferdinanda, paní Müllerová?” otázal se Švejk, nepřestávaje si masírovat kolena, „já znám dva Ferdinandy. Jednoho, ten je sluhou u drogisty Průši a vypil mu tam jednou omylem láhev nějakého mazání na vlasy, a potom znám ještě Ferdinanda Kokošku, co sbírá ty psí hovínka. Vobou není žádná škoda.”
„Ale, milostpane, pana arcivévodu Ferdinanda, toho z Konopiště, toho tlustýho, nábožnýho.”
„Ježíšmarjá,” vykřikl Švejk, „to je dobrý. A kde se mu to, panu arcivévodovi, stalo?”
„Práskli ho v Sarajevu, milostpane, z revolveru, vědí. Jel tam s tou svou arcikněžnou v automobilu.”
„Tak se podívejme, paní Müllerová, v automobilu. Jó, takovej pán si to může dovolit, a ani si nepomyslí, jak taková jízda automobilem může nešťastně skončit. A v Sarajevu k tomu, to je v Bosně, paní Müllerová. To udělali asi Turci. My holt jsme jim tu Bosnu a Hercegovinu neměli brát. Tak vida, paní Müllerová. On je tedy pan arcivévoda už na pravdě boží. Trápil se dlouho?”
„Pan arcivévoda byl hned hotovej, milostpane. To vědí, že s revolverem nejsou žádný hračky. Nedávno taky si hrál jeden pán u nás v Nuslích s revolverem a postřílel celou rodinu i domovníka, kterej se šel podívat, kdo to tam střílí ve třetím poschodí.”
„Někerej revolver, paní Müllerová, vám nedá ránu, kdybyste se zbláznili. Takovejch systémů je moc. Ale na pana arcivévodu si koupili jistě něco lepšího, a taky bych se chtěl vsadit, paní Müllerová, že ten člověk, co mu to udělal, se na to pěkně voblík. To vědí, střílet pana arcivévodu, to je moc těžká práce. To není, jako když pytlák střílí hajnýho. Tady jde vo to, jak se k němu dostat, na takovýho pána nesmíte jít v nějakých hadrech. To musíte jít v cylindru, aby vás nesebral dřív policajt.”
„Vono prej jich bylo víc, milostpane.”
„To se samo sebou rozumí, paní Müllerová,” řekl Švejk, konče masírování kolen, „kdybyste chtěla zabít pana arcivévodu, nebo císaře pána, tak byste se jistě s někým poradila. Víc lidí má víc rozumu. Ten poradí to, ten vono, a pak se dílo podaří, jak je to v tej naší hymně. Hlavní věcí je vyčíhat na ten moment, až takovej pán jede kolem. Jako, jestli se pamatujou na toho pana Luccheniho, co probod naši nebožku Alžbětu tím pilníkem. Procházel se s ní. Pak věřte někomu; vod tý doby žádná císařovna nechodí na procházky. A vono to čeká ještě moc osob. A uvidějí, paní Müllerová, že se dostanou i na toho cara a carevnu, a může být, nedej pánbůh, i na císaře pána, když už to začli s jeho strýcem. Von má, starej pán, moc nepřátel. Ještě víc než ten Ferdinand. Jako nedávno povídal jeden pán v hospodě, že přijde čas, že ty císařové budou kapat jeden za druhým a že jim ani státní návladnictví nepomůže. Pak neměl na útratu a hostinský ho musel dát sebrat. A von mu dal facku a strážníkovi dvě. Pak ho odvezli v košatince, aby se vzpamatoval. Jó, paní Müllerová, dnes se dějou věci. To je zas ztráta pro Rakousko. Když jsem byl na vojně, tak tam jeden infanterista zastřelil hejtmana. Naládoval flintu a šel do kanceláře. Tam mu řekli, že tam nemá co dělat, ale on pořád vedl svou, že musí s panem hejtmanem mluvit. Ten hejtman vyšel ven a hned mu napařil kasárníka. Von vzal flintu a bouch ho přímo do srdce. Kulka vyletěla panu hejtmanovi ze zad a ještě udělala škodu v kanceláři. Rozbila flašku inkoustu a ten polil úřední akta.”
„A co se stalo s tím vojákem?” otázala se po chvíli paní Müllerová, když se Švejk oblékal.
„Voběsil se na kšandě,” řekl Švejk, čistě si tvrdý klobouk. „A ta kšanda nebyla ani jeho. Tu si vypůjčil od profousa, že prý mu padají kalhoty. Měl čekat, až ho zastřelejí? To vědí, paní Müllerová, že v takový situaci jde každému hlava kolem. Profousa za to degradovali a dali mu šest měsíců. Ale von si je nevodseděl. Utek do Švejcar a dneska tam dělá kazatele ňáký církve. Dneska je málo poctivců, paní Müllerová. Já si představuju, že se pan arcivévoda Ferdinand také v tom Sarajevu zmejlil v tom člověkovi, co ho střelil. Viděl nějakého pána a myslil si: To je nějakej pořádnej člověk, když mně volá slávu. A zatím ho ten pán bouch. Dal mu jednu nebo několik?”
„Noviny píšou, milostpane, že pan arcivévoda byl jako řešeto. Vystřílel do něho všechny patrony.”
„To jde náramně rychle, paní Müllerová, strašně rychle. Já bych si na takovou věc koupil brovnink. Vypadá to jako hračka, ale můžete s tím za dvě minuty postřílet dvacet arcivévodů, hubenejch nebo tlustejch. Ačkoliv, mezi námi řečeno, paní Müllerová, že do tlustýho pana arcivévody se trefíte jistějc než do hubenýho. Jestli se pamatujou, jak tenkrát v Portugalsku si postříleli toho svýho krále. Byl taky takovej tlustej. To víte, že král nebude přece hubenej. Já tedy teď jdu do hospody U kalicha, a kdyby sem někdo přišel pro toho ratlíka, na kterýho jsem vzal zálohu, tak mu řeknou, že ho mám ve svém psinci na venkově, že jsem mu nedávno kupíroval uši a že se teď nesmí převážet, dokud se mu uši nezahojí, aby mu nenastydly. Klíč dají k domovnici.”
V hospodě U kalicha seděl jen jeden host. Byl to civilní strážník Bretschneider, stojící ve službách státní policie. Hostinský Palivec myl tácky a Bretschneider se marně snažil navázat s ním vážný rozhovor.
Palivec byl známý sprosťák, každé jeho druhé slovo byla zadnice nebo hovno. Přitom byl ale sečtělý a upozorňoval každého, aby si přečetl, co napsal o posledním předmětě Viktor Hugo, když líčil poslední odpověď staré gardy Napoleonovy Angličanům v bitvě u Waterloo.
„To máme pěkné léto,” navazoval Bretschneider svůj vážný rozhovor.
„Stojí to všechno za hovno,” odpověděl Palivec, ukládaje tácky do skleníku.
„Ty nám to pěkně v tom Sarajevu vyvedli,” se slabou nadějí ozval se Bretschneider.
„V jakým Sarajevu?” otázal se Palivec, „v tej nuselskej vinárně? Tam se perou každej den, to vědí, Nusle.”
„V bosenském Sarajevu, pane hostinský. Zastřelili tam pana arcivévodu Ferdinanda. Co tomu říkáte?”
„Já se do takových věcí nepletu, s tím ať mně každej políbí prdel,” odpověděl slušně pan Palivec, zapaluje si dýmku, „dneska se do toho míchat, to by mohlo každému člověkovi zlomit vaz. Já jsem živnostník, když někdo přijde a dá si pivo, tak mu ho natočím. Ale nějaký Sarajevo, politika nebo nebožtík arcivévoda, to pro nás nic není, z toho nic nekouká než Pankrác.”
Bretschneider umlkl a díval se zklamaně po pusté hospodě.
„Tady kdysi visel obraz císaře pána,” ozval se opět po chvíli, „právě tam, kde teď visí zrcadlo.”
„Jó, to mají pravdu,” odpověděl pan Palivec, „visel tam a sraly na něj mouchy, tak jsem ho dal na půdu. To víte, ještě by si někdo mohl dovolit nějakou poznámku a mohly by být z toho nepříjemnosti. Copak to potřebuju?”
„V tom Sarajevu to muselo být asi ošklivý, pane hostinský.”
Na tuto záludně přímou otázku odpověděl pan Palivec neobyčejně opatrně:
„V tuhle dobu bývá v Bosně a Hercegovině strašný horko. Když jsem tam sloužil, tak museli dávat našemu obrlajtnantovi led na hlavu.”
„U kterého pluku jste sloužil, pane hostinský?”
„Na takovou maličkost se nepamatuju, já jsem se nikdy o takovou hovadinu nezajímal a nikdy jsem nebyl na to zvědavej,” odpověděl pan Palivec, „přílišná zvědavost škodí.”
Civilní strážník Bretschneider definitivně umlkl a jeho zachmuřený výraz se zlepšil teprve příchodem Švejka, který, vstoupiv do hospody, poručil si černé pivo s touto poznámkou:
„Ve Vídni dneska taky mají smutek.”
Bretschneidrovy oči zasvítily plnou nadějí; řekl stručně:
„Na Konopišti je deset černých práporů.”
„Má jich tam být dvanáct,” řekl Švejk, když se napil.
„Proč myslíte dvanáct?” otázal se Bretschneider.
„Aby to šlo do počtu, do tuctu, to se dá lepší počítat a na tucty to vždycky přijde lacinějc,” odpověděl Švejk.
Panovalo ticho, které přerušil sám Švejk povzdechem:
„Tak už tam je na pravdě boží, dej mu pánbůh věčnou slávu. Ani se nedočkal, až bude císařem. Když já jsem sloužil na vojně, tak jeden generál spadl s koně a zabil se docela klidně. Chtěli mu pomoct zas na koně, vysadit ho, a divějí se, že je úplně mrtvej. A měl taky avancírovat na feldmaršálka. Stalo se to při přehlídce vojska. Tyhle přehlídky nikdy nevedou k dobrýmu. V Sarajevě taky byla nějaká přehlídka. Jednou se pamatuji, že mně scházelo při takové přehlídce dvacet knoflíků u mundúru a že mě zavřeli za to na čtrnáct dní do ajnclíku a dva dni jsem ležel jako lazar, svázanej do kozelce. Ale disciplína na vojně musí být, jinak by si nikdo nedělal z ničeho nic. Náš obrlajtnant Makovec, ten nám vždy říkal:,Disciplína, vy kluci pitomí, musí bejt, jinak byste lezli jako vopice po stromech, ale vojna z vás udělá lidi, vy blbouni pitomí.' A není to pravda? Představte si park, řekněme na Karláku, a na každým stromě jeden voják bez disciplíny. Z toho jsem vždycky měl největší strach.”
„V tom Sarajevu,” navazoval Bretschneider, „to udělali Srbové.”
„To se mýlíte,” odpověděl Švejk, „udělali to Turci, kvůli Bosně a Hercegovině.”""".encode('utf-8'), dtype=np.uint8)
    
    res ="".encode("utf-8")
    iteration = len(secret) / 64
    isFloat = False
    if not iteration.is_integer():
        isFloat = True
    iteration = math.floor(iteration)
    for i in range(iteration):
        block = genKeyBlock(key, nonce, i).view(np.uint8)
        res += np.bitwise_xor(np.bitwise_xor(secret[i*64:64*i+64], block),block).tobytes()
    if isFloat:
        block = genKeyBlock(key, nonce, iteration + 1).view(np.uint8)
        res += np.bitwise_xor(np.bitwise_xor(secret[iteration*64:64*iteration+(len(secret)-iteration *64)], block[:(len(secret)-iteration *64)]),block[:(len(secret)-iteration *64)]).tobytes()
    print(res.decode('utf-8'))
    end = time.perf_counter()
    print(end - start)
    exit
    if sys.argv[1] == "-g" or sys.argv[1] == "--generate":
        print(genKey())
    else:
        print(decodekey(sys.argv[1]))
