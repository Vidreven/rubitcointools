require 'scripts'

describe Scripts do

	s = Scripts.new
	addr = '1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa'
	multi = '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'
	test = "2N9hLwkSqr1cPQAPxbrGVUjxyjD11G2e1he"
	scripts = ["76a914721afdf638d570285d02d3076d8be6a03ee0794d88ac", "76a9146a7051af35aeff4d015fded1a26782bab83951f288ac", "76a914be1dd65604e271beb7fa032be4c3a7f39ce3cdbf88ac", "76a9149b08f04cbd36711450c3844ec954b2c20aff770288ac", "76a9147055b496bc56c841d32d9ed3d6b1a04e8a86600688ac", "76a914cca08ea2b59d6096159be369b3895a1ee7734a5188ac", "76a914bd55cab7c31d5773fb39228a0cd3b05f8ef5fdee88ac", "76a914f294645361beca289edc2336f55818d341f029b588ac", "76a9142903bf1193104f42d746330bc529422b214ddc5988ac", "76a91498463d6c81b930e1a8e9620ef68d2a79a901d38b88ac", "76a914d7595c35d432bd9c184a70723e065ee38544187a88ac", "76a9148efbe6031bc247bc186dfc6823bef42df63c5d7388ac", "76a91479830e6c6d0cf065f192749759004f8e4b8f446d88ac", "76a91449b135f899b88c60b25fd274403556ac052cfb8788ac", "76a914bd55cab7c31d5773fb39228a0cd3b05f8ef5fdee88ac", "76a9142903bf1193104f42d746330bc529422b214ddc5988ac", "76a914b5968dd49b6e71fa7bc8f8f9e0f7eb161bab67ee88ac", "76a9147055b496bc56c841d32d9ed3d6b1a04e8a86600688ac", "76a914ec2fb0fb78cb412b11d0a0b927035b7897f00dac88ac", "76a9146d746d1b2af573ec5bab50e79b4d711db73e762c88ac", "76a914d7595c35d432bd9c184a70723e065ee38544187a88ac", "76a9142ccbd9a4386e055023f87d5e0ea5a21f3982183b88ac", "76a914a53cd20c844ab2a28dc297e7054e24259ae4ae6a88ac", "76a914479d8b6429866cc6d25bcb822a377f8e1005c7cc88ac", "76a914ee25ad88334f2cfd8b388fb1bcf349bce43b37ab88ac", "76a9141b57f8e7c9b6992e17ff4ed1f18b0c1ddad8fb9988ac", "76a914d7595c35d432bd9c184a70723e065ee38544187a88ac", "76a914bd55cab7c31d5773fb39228a0cd3b05f8ef5fdee88ac", "76a9146e4c7dcca0a6ddf680a67e6967d8826ce4463d0288ac", "76a9142903bf1193104f42d746330bc529422b214ddc5988ac", "76a914c8dd4ba99f575da7745780eb8aec80720185336788ac", "76a914dd6867ef6603ae4d7910f2a184a1e44270b7c1f588ac", "76a914e92d1cd93f6492f3516521491175c1adc7fdb31e88ac", "76a91457b5a9c2b2a353f8f8fac89c2543b84b6c4929cd88ac", "76a9149a347729d35a4e07ffd5c2ffbc49d41d232b23eb88ac", "76a914acbb9b9e0407af5fe18aacaa3f29732e319ebc2888ac", "76a914a00fbc41f10a1fcfe6fdb581b7b9dd81bc21460c88ac", "76a914bd55cab7c31d5773fb39228a0cd3b05f8ef5fdee88ac", "76a914942b9df3ce368288680750d0c6e90dce9cf27cff88ac", "76a914a288b2cd19723448734fd0d27d3be5703645384588ac", "76a9142903bf1193104f42d746330bc529422b214ddc5988ac", "76a914d7595c35d432bd9c184a70723e065ee38544187a88ac", "76a914664a82fd937edf8b407d900a4e12b3f82130d8c688ac", "76a91482038f362deb625fe596667f9ce9440ebd92f47388ac", "76a914e8c7f93b84e1f06d739b7ad6dbb3f97a5d249de288ac", "76a914debd782f85ad4f789f001f6e4f24da4cc5a6718c88ac", "76a914d6ce3e35a300f7c351701915972a077375851bbf88ac", "76a9142903bf1193104f42d746330bc529422b214ddc5988ac", "76a914a72f1625491bb8a496eea20296fb01174e809ada88ac", "76a91499109b8343a0609e3913c1bd254d61d803c29f9788ac", "76a914a53cd20c844ab2a28dc297e7054e24259ae4ae6a88ac", "76a914f8b4fa9467404cc4f55b7d89b81a81a68b02cc9d88ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a9141caba5df97c1614208446342da2610baee9457b088ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a91451e599a8f78b14599f3aeffc12be0d24b236d76a88ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "a9145abbccbdeb4a36aefabae5b3cbf022cd6b4830db87", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a91438542e0ddce5533ab5ef0322231c9f3d470c4c7688ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a914af837bb32ea8323407ed9fee4c1a55268a68404188ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a914863af23d97e6e013bf1427c671aecc553ac948e588ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a91493a51ddf7f283ebadd87769efd8b6278b42e73a088ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a9148b4d4a2a733c7335bb157c729d7563d4b53d69f788ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a9147afa194a52feb0ffcd79f90171aadbc170279cf588ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a914bc9f44a648794573cac1c083e3e1e3495a2048ed88ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a914c7e655db8556ce8fafb374d795cb9fee5cd1f74188ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "a914c37ad784b9b18a16ea14bad0a3c88400efce975287", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a914b0dfe969ee88a14a55e8e056d9e48ed52c1a1c1b88ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a9143d9aced0505cf11a4cbe0f19e27ab4d783e430c988ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "a914a5cac9ed2278ecfe08ae9a0738f90af103edf45587", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a914bea15c8b0c452210d3fa11124fa6ea153904e09388ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a914db51a1e6df769dd91364cd15fa9c9ca611c8db7e88ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a914c81e6838ea62d3970beb814ed2f8c1f1fa1b46ad88ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a914d16f9abb521962eaf7b3487c7a76317ab4eacdd888ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a914f6d3e19f98358b9f8346ca7f38e8ff24f05f8fad88ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a9144249742ebee1f20ad1f03ee0854f4de47efc1c6288ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a9147af62e0876ce145adce0dbcc4782ef4d476f78c088ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a9143cc1d1d8a2b127389cec69586346d5f2602ae8e988ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a91418588b6326d7346fc9be06969a288455a327824688ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a91429c8e7dd769d333cd5c4a9eb31fa5830d362777388ac", "76a91429c8e7dd769d333cd5c4a9eb31fa5830d362777388ac", "76a91429c8e7dd769d333cd5c4a9eb31fa5830d362777388ac", "76a914af0aec25714cd08c673fcb459f14aeef69f40b8e88ac", "76a91405d602c8c4b19bd7aa58a554a7fc9769d6bf6ac088ac", "76a91461275197d8ad9addeaa4b5d0f6952b1e3894547988ac", "76a91421e82187628d4438302fed5557416f0123e5aaab88ac", "76a91421e82187628d4438302fed5557416f0123e5aaab88ac", "76a9142b60411dee962c9ece3649a8cc13d281e8178e9488ac", "76a914b73f4018e17639ba49952f24bdf4825c517ee5c988ac", "76a9140971c8b5ca769e444d09d7f1712bb19c4a64d7c888ac", "76a914638dba3031d185afe04887aba3a5e9972b4a7b4f88ac", "76a914aa12af9b511f7efad12e7feda61d7c872ed65e9d88ac", "76a9142bff92d6c4ebff7221cc907c24435faa3da0c6f688ac", "76a9143d26bedb35618d08b4319a77b35537aae7a36c7188ac", "76a914a62efd2ca8d9234d6fa95b2b25a306d4ced88d2188ac", "76a9149a6930fae4b57804e8dc062232ef4eda9f4e71b188ac", "76a91475b84ef55309f98edcf08f52d0ad9cbaee0f9c8a88ac", "76a9143fb257cdd961b122b8b11b27afa99d3cdbcbd30888ac", "76a91426d6bb8adbbdb0c85451de50afd6eac1edf672ab88ac", "76a91486a72741d5e8212ac414e33be5f7e113d13519a488ac", "76a914eaeef5af0f55e3f6bb4547c5c4fbb4e043e43ab188ac", "76a91409903802ee611e636cccbe21c142e425678a6f3188ac", "76a91447165bc9c785aa213c1618d88f017ba1e4837b7788ac", "76a914df085bb676c8b49ef7555d178cdaac5e55e6df0e88ac", "76a9140c59b390d4c0f5b93bd64d908e9dc10b1070479588ac", "76a9143ef84b5bc14b9f056a14b4a376acad16bf42d1ca88ac", "76a9147733666de3dc0f602551135c2a204355c3da6f5088ac", "76a914690a0cd849007be2be91ca6cdc755540f1e77ebd88ac", "76a914a5d5a8545a512830e62c97c8ec3c67e3f9620b3988ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "76a914091feb7a35215aa89972726abf88737e1415f84e88ac", "a9143043e436c16b857d155a33f3a9aa61312b51a59887", "a9147c1fd884fe0dec8a146ab6fcbd2883dc6a347ea987", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a914e98c04d30e490b62cc5512044f4200189514848888ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a9145ef8d20e7e3e7aa98a716ef09a93dbf35a74b6b888ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a914c2fa7334a9a997826cb98b61c0fb5963ea7453c788ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a914da98636ccfd0688ffe25ca2040903abc192d8c5788ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a914c64358e17323fc5f2fa28aefa6b03c2820d9caec88ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "a914c97d2ee8c7d4f5824bfd419c07dfc6eb39cc896c87", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a914f4807b333d0045f63b0c6fb33d0fb6034216352688ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a91451661cb52ea70405d0ab6b6b3071d9cb75a6c8fc88ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a914e032f012a7099c46a6f9b33075bfe196eccf960788ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a914d3a8a1789be9915dff79e503c6c76569593b286688ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a9146cb4062eaa2dca9623517b02173bc94e2554855a88ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a914129886b31f1dc8bd8dcde623e76e1bedadc0a21588ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a91469161e5fe7caaff9b8f53b56ca453342d19d8b1e88ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a91474e69a4fbf1d3f5337011b858a84f71fd3d81eb488ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a9141794eb14fcb63b0fbe6c276e9e9206585e2a370d88ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a9148827f286b641ee00570eb27c2cbc4962ad80118288ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a91471b0eeef7438149f4163549b8e073172308e67ed88ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a91455b2c6d524c0698b1d5366bd4906f83b515bf85d88ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a9144f32be4adde73b752ebf645deda33c1020f6001988ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a9147304f9f6a4dd1c975291c73bd89660d6429b01b188ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a9141df9dc3c7a0bab9211a132e4844e4d74910abe4288ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "a914cdfb90855844e04e734c071c271f431c75023e0c87", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a914d2daa0c468a9e884b05427797cae66977669853588ac", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "a914cdb3db60be633ba7d8338f84f2e47ffd9a9dd44487", "a9143203aae17ce870fd07fefaf90dff3daf1ce4642587", "76a914abf76899ae9e516cdd1449d714ddf8ff64f2041088ac", "a91455b3d194c4b9fc44c8a7867235dcb75c3e81e32987", "76a914651434f59f2a3fa50762a51212167feeec1bd44888ac", "76a914baca5bbd6c3e7929b63540968d01f3a4f2248d0e88ac", "a91498d6dfaef6674a2e8ea184c0e0e957aacb222f3187", "76a914a04ebe73dfc9e2fcb68d8670911808e37184fb7c88ac", "a914aabba8f2d2f0be464e02f0503b41d163114d79cc87", "a91462a1688d6b0c8059055561545452c06b6ebc06ce87", "a914f10f4577819ba7425bcfab742cb8ded5eb6e0c7987", "a914133fca5213ca85bb6e7e7f96d12aaf03b406c57d87", "a914292958410e2e60c734847ebd803b4d3b8b691fc687", "a91404d5ae6f2f4e7efb8a1e12dc34a33b03566547c587", "a914f10f4577819ba7425bcfab742cb8ded5eb6e0c7987", "a914d12228945d77232901320c36f1a13177f14022d787", "a914364bd7b72e98273255d540cb38dfc6cb3951bf3387", "76a91468196f1e65c297c0f960dd4320528d0d8a4a916188ac", "a914bb774873499a47d0c1eba783adda1841c9e0a11887", "76a91400ef0d518734b8fa40aa30b8453e73afa5c110e088ac", "a914735d4de855597997b21588cc78ca2db696be1c5d87", "a9145fc9aab590661ac25e907189b440498337a8e12987", "76a9140a77a27eb5096aa54869b8332240a5cefac8cf7d88ac", "76a9149db49e97067a53fbaac2eb084201bd76613ac50688ac", "76a9147540ae61a0505d05664250518506a1113d93e05688ac", "76a9144e56746b93661eaba9d21a992b09adc1ded2088988ac", "76a9146f454a06805d006c488dc12194005f97079e6c5788ac", "a91468f4622dd90c4df037f7e6cb47cee4a46ece8fb887", "a914993b101d0827e61dd981055c08ea90a1d8d0840e87", "76a9147de79a66253c88cf8b685751f9bca02c52ab1fdc88ac", "76a91432afc039fa7d2a2675b175067ef1c211aebf594c88ac", "a914033cf72742732799da5a1cecbece77ff25d7868887", "76a914c5683a0b34ab9415147cd573428a00b53963554388ac", "a914b5bcb017fea9df720d470c7a3604555a587b958f87", "76a91461d96c7d6e859598c32bfadcbb0c76ed2912e81688ac", "76a914ae41b5afe0cf945762e5506f076e46cc147e189788ac", "76a914aac5abbd84766f250afb9f61ee72b530547ec37588ac", "76a914bc4f3505021ac03560f03c0047cd09316c6d979a88ac", "76a914e7dc1dfa87ed83c309005fa7e2af2229a5277c6788ac", "76a9147d8a49e677ca8c61e0a9e091b23756249e7eac1688ac", "76a914f325f94bf7161da48fd155194c451998085a843288ac", "76a91478ada5f4a450449a4269d5964bd7bbd18344102288ac", "76a9141331f2fa3e0b63ff11bb7e8a7a376b4d55165f5388ac", "76a914eb5ad09b4881ef07759ddcdb86895583f8e00ae688ac", "76a914dca27d00c507766b65724e3fcb86eeb79e41c37e88ac", "76a914382260ca84eb6a113445163e3bf87fec50e7bbbb88ac", "76a914a4357bf37c74c62c6df7a2b02a4dc5cf54e4f48a88ac", "76a9149d226143b73c29d488f6d10a3c4d883ee2e5776c88ac", "76a91475c1ee5fdc1b61aa48a67e0aa0a26c07b85d90d788ac", "76a91494770652b4c949d46c8e0b3f0a573a4834a5db9e88ac", "76a914e09000895986fd4c16f3e62e0b11c264c0b44eec88ac", "76a914af37e0a41bc8088eff6a8c7c1ce2e7cd013c372288ac", "76a914ae04bcf5a4e0083c369a2d5fc70b9923921c0ded88ac", "76a9149d3a7b110299c444df48b3a13ccaaeaf786c0cd688ac", "76a91454246b5a148423d3cf9398379fc4077c222c529d88ac", "76a9149336eb89be5f594d4d1e682ccbaad1aff89d181f88ac", "76a91495277cd9fd0488e637f8b059949b4621e151572088ac", "76a9149e0fe87e93ce8d0c6f94983e4d167db4f774fd8788ac", "76a91422375be3ff51975b08a0273c378fc2581f4001bf88ac", "76a914c37fd535e4db3efb90d99a2383769f14e1adfe2788ac", "76a9148d18e8bade62d746c0a234975ec5b1349e47e8f688ac", "76a91498890e0fea94774d3aa4bd53b038daf8dbd6fd6988ac", "76a9149ddf8df5f2a1c428a6c64a8fb15338aec800f88788ac", "76a914baad9a982923655e03228376f048c9c1280825ef88ac", "76a9145c5acaee7188cc0092cba3fcf7a268ba6f5fce5f88ac", "a914735d4de855597997b21588cc78ca2db696be1c5d87", "76a914195d05c928c00bbcf9bf7a766b6f6dc22f6ea3be88ac", "76a9142696a0c95cc548a4ef1f7387ea6acb836550187e88ac", "76a9149b1ae14a7e6275b10a0229fcc7274854cccab95188ac", "76a9145cf97f9127e5dd58fd48ef7dc718c193aff10d2c88ac", "a914b655ea195d66393ba96731564841fe376197beab87", "76a91409cd15621b101eca0de0e6d3786f6aeaf497b34188ac", "76a914849ae98b6633ab9d90f4c65586febfb62dd93baf88ac", "76a91421d40dcdc1ed176f00af01adee37a8dad017f7f188ac", "76a91441f7868e7f7fc1d91d72ea98190965ed30eac92688ac", "76a914e69131c9488c6caef5835a9dabd0286da82dc5db88ac", "76a914b7b3d9ba934b4d77b9f1a13d95489b17047ef41988ac", "76a9149573daa5e5438d7e6ab2d2f2a0c82aeaf3f1c80688ac", "76a914d271820fe278f9efb75febc0ac2e35a64ea2ae0688ac", "76a914491ecc6dc9f530ddfdf44880d95c660434b83b1a88ac", "a914de68f8a7701df81d36a78f691629c7804123136f87", "76a914c965d2cdaa821fdc6ae7fc3f00c9fdfc6f979b8888ac", "76a9144eb223ff5a6e76cbaefe7f972d858a926e6f7eb388ac", "76a914c43f9cc860e7ec4e441dfef54f2822e71fc2d44388ac", "76a914897512418e96f1a0531000106f4929559e85ace988ac", "76a914f81217ec127bd30a90e34c0344cb0a9066b8f46f88ac", "76a914c0b51e8c4e9f471b1651e913469286d1b6e1fa9e88ac", "76a91495ca67aea1fcc4933792bbe850454e268ef2a89d88ac", "76a91402cea20bc21b4102d1126209778b94225ceb6ffd88ac", "a9146355d7cf394dbb7b67cf94cb6b9da232b35225e187", "76a91430db5e8917140ceda35e6ff341716a33bdeb24ca88ac", "76a9141aacf5cece33aa5f068f676834e4ae4ac8a45bde88ac", "76a91467ae3a0b741cf24e880bd435e37570f07df35bed88ac", "76a9144762fa63bfe967491d61ecafd70bd52f1e57cace88ac", "76a91414a574b0d6fceb260f065f360b8d3c15deab2d6288ac", "76a91413e3ec233f121a377b4e11eadee8f6574f97e70488ac", "a914dda7acc51249a8a098c2b20be25f784061139bd187", "76a914b4980cbe0cd32e597885bfaec405ec96567f283d88ac", "76a914a21f54c4efdf50f7be296623c0efac909e33cbd388ac", "76a914e35b5700db56135421ce38fbe50c59274b39f0cb88ac", "76a9147797156ebb944c0f034c824c4dc426086da795aa88ac", "76a91423e6a8b3d3dfc4cc4830af121701c7e5b3b2da0c88ac", "76a914ee46b3c8a825e89e3c599146c8b336d74e3b0eb188ac", "76a914d75d491319068302866d55027efbddb178fe4abc88ac", "a914a4d0690fe08186034e10377033c835b6f6ea929b87", "a9147a6978832e3c755b4acbb207072a5504893850fa87", "a9142924af27ab4070e8cb5f740ecadc791704d141b987", "a914bac14fa7bc0ff66238cad3d4c1a4335b893c860d87", "a914b4f865b2a44e4d1ff29bb97f136df2e56b736b7487", "a91492769d9b90ab880aca61c1aaefd8dd0cd35ce2fd87", "a9144321612ac976bae33c9677a06ade4efc2801a66f87", "a91449a7a3c6deeb3e49287a9b66951e1eb2a866da0187", "76a914d156768018c0741fbe23bc57ee905c0ab1f4ae4588ac", "76a91474769c131a6eb31f983b84616aa13a883750c67a88ac"]
	addrs = ["1BQLNJtMDKmMZ4PyqVFfRuBNvoGhjigBKF", "1AhoBQEHByDeQjtGNZQpW53VG81spU5F3M", "1JLF8aRXjLVbVVhfZQ7n3NC7oGJs6ue9i1", "1F8kSobqmyLqzmkibDGXFLvredxjvGntFV", "1BEyMQLTYKPnXP3NoqA5LpUyFqGMnyx6wU", "1KeyBqngpC6zH9Yu83YT6cbCGuzRzBGcNS", "1JG7VBQHPqGPNVu7CHy4kZssgDXvhNqwXj", "1P7eHscuBHqkQX5bKsBPZe1pqXH7nvNXnW", "14jsCAgEoATL541EJJVoBon35p6kdv4rCV", "1Et9rWr7fkMn9XjiyX9rtufzmxwtrJVHpj", "1LdfL6jULM3yQChZSFbio214vYd647o3UR", "1E32iTJXksPCfGw3scP7d6aEGPfuPyoEBr", "1C5VmAccH8awG6BpsuvBonqoFhUHrcG7Ji", "17iecpzx9iM9AuFdYMpCSygqSiahyeyHKR", "1JG7VBQHPqGPNVu7CHy4kZssgDXvhNqwXj", "14jsCAgEoATL541EJJVoBon35p6kdv4rCV", "1HZ9fQ79Aq4ro845jwurEDgPmvxz7yymNt", "1BEyMQLTYKPnXP3NoqA5LpUyFqGMnyx6wU", "1NXqbvbvzfoHzFmF2cBamoMsDJF4zac2qZ", "1Ayk8LvFnz5goHrYsGAQbXoaY1yrUWbvhX", "1LdfL6jULM3yQChZSFbio214vYd647o3UR", "155rwCVRjpca98PnLRRhdR5dLf7KRBsneJ", "1G4hMY1gkKQY18nzSar56RBjF85L7MxFQp", "17Xfi1Cr6tCEzBoBmBMBwfrFA9UKKboEam", "1NiCxZSCByiLW2b84EMYusN3k5o4k6hxoA", "13VadbrzGDywaFRUe753bbM1xUdMHnPcgh", "1LdfL6jULM3yQChZSFbio214vYd647o3UR", "1JG7VBQHPqGPNVu7CHy4kZssgDXvhNqwXj", "1B4CxpQCswxEpcgL7pQX8roZz4FQispS7P", "14jsCAgEoATL541EJJVoBon35p6kdv4rCV", "1KK5FFZAVkGWEzjjpGsxWYBC5RKNu6a1sN", "1MBhQeimfBAHMrsXyUsiB6X16MjTKKf6hH", "1NFvVBWLkcvQiSqguyQegPbC9jnGzq4gJ5", "18zmQs9WgSSgQcSLPhwidQ3wunfueznCdr", "1F4Muudky7UmHJkPZ4BM1XxacN3M6kXxLF", "1GkKyDhD4iYn7sewFgeDCe6Dx5p8QqeRd3", "1FbKy1NFwzgQru8mvfcrXaonfZ2R89tMzc", "1JG7VBQHPqGPNVu7CHy4kZssgDXvhNqwXj", "1EWTFxHsS3goBsZccxREGMUdhbiEk1H1Nf", "1FpQE3wsSFhUSuRCehMoCMPkc2dKtFsR2M", "14jsCAgEoATL541EJJVoBon35p6kdv4rCV", "1LdfL6jULM3yQChZSFbio214vYd647o3UR", "1AKsBjHjp4GFVmbbKipDrNamwmuBu39Xya", "1CrT7FYmkoFqmd5WZLfLk5PiyCto2VPqCr", "1NDqKusHZrkHB1KjrG6cC2Vtj3dyDWZftq", "1MJjzA4iFwGW5pvGYQ3ceYXLsipCC8CVLz", "1Lang4tLNs6hzZ5EoHm2sbUnvwcb2nx2xL", "14jsCAgEoATL541EJJVoBon35p6kdv4rCV", "1GEzFfV2JbAwK5vdKACusjD83Mb3Xp4EPE", "1ExLHFvwxaudd2T1ADjskEss3AcpDVq5W6", "1G4hMY1gkKQY18nzSar56RBjF85L7MxFQp", "1Pg3PCns7mfFpUfpmj5EwsHxKzKNY6L6SK", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "13cbYgQYpdjJFdXqKqB8MucjLkKeYz1eXk", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "18U2nSefB5KKp69srnq3yqAG1qrHiZgoiA", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "39xmiN9haBxKT2jPvhd6i4gmhHhL9dcxn7", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "168qgfY8cR1t1EofsHRgdXq9GJH6rr2ghb", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1H12mBe1dCnVbhVB5BzWQcZ5iiDEFeHaUd", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1DEkAN36Gsu1nVDetGNfFu3f7SH1yCVkCB", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1ETg8i4TwSu7uLYDH2PSejoebrq6mWf4pX", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1DhZWrATzCck9GsYSBUsWzdzaayoDvBpSN", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1CDF3aAtsVHtjYhzHsuFsUHz1CkERae54h", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1JCLqDBZfDrhzN3gZ6VJKCPyxEhjJse1Tm", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1KDyQA7SCvgv2rNDhsDJcBZ4N4VbySmd29", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "3KWcr9rCqydSndAH2zLSfx6vNjkDMZxcXk", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1H8EAReEVcVjvdsLLnZYZgXug8D97BHRhW", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "16cjfwZjA18y51K32in28CPyprqUnprDWW", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "3GoeMCx6T7DSSdU8pjPAwbF6JS44Hb93H3", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1JNxh3PLcJhsXbGyqBwn41Z7Vbm4RyPrFR", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1Lzemw2U6AWxQVGE2jtJTbuzy14LabmYyE", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1KF8a6Co8cJJEdoFh7m3ysNPGrczg1XxTT", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1L6PvWDJi8pKm5JSZLwRHiUhJHiCLJhh3c", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1PW73xupnny3JXRHYAWYacemc4jTXhSRiW", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "173VbKjTHzLgsZmr6sJAhKjMdjzPqJX5tZ", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1CDAMH4HwzTEwNfU9AgfSBFmMqpVdt1RiH", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "16YFjLh4GvVTrndKaBenoyfHroH8gW3qKn", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "13DjHnNuGBGmyP48bGHbAuj7Dfjsc5K6wA", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "14owP3HYyPYqpLDKmYvMUJYu2VHTwkNasb", "14owP3HYyPYqpLDKmYvMUJYu2VHTwkNasb", "14owP3HYyPYqpLDKmYvMUJYu2VHTwkNasb", "1GxYLUZZzfDs392W3gTebLARJ2STamR5fC", "1XrkhLfFyxpbHPjM9NRNz3JyPf3HVdCDt", "19rheXBQeRgz96aHhqhA8yaNpxT3dhxGNi", "146HP5EuPcpFEG5i4gVYBtpBGAz8sQxwoS", "146HP5EuPcpFEG5i4gVYBtpBGAz8sQxwoS", "14xMN7ude1AQZcNsbxkwhe585rHah3awoH", "1HhvRpU4aj5CX2Y9AMX2YyAk6nyfHKm5ct", "1rwPaawMarhC1KRZBuXJe9aT2RkPZkh1w", "1A5PgNqZhd9D6UnbsNLrTCTKUginFHJSMx", "1GWGFwDJGnEWyHxkdS5meR8Anbz1imyVJj", "151eDpA25Xf9zJmJDDHpF9iSpCFTLwa5wd", "16aLdnjJwsD4su7962oS2b5hh65eHxo3hF", "1G9hThGLdrgM5gipGF5T8HjTt75nXcdNBg", "1F5T5N5r1Q77FoNMS3uEnDosnXdaDRMSZA", "1BjSrRGdPK2PB8r9XKKewJ955YRg8qAeRc", "16ooDaF2VCSagNwkiHANGTudoP5BSzZ5hc", "14YMvAwGDq7YaABeyxPTXBT31hasG58Qkj", "1DGynixwQmYZ5Ha5cSH7m7dEn4KiNLgsZg", "1NRDP6mnEkQctXkZ59QX8dRvAVSt4KXWFn", "1sZrDzYa2wuhUAqDfon3GyNqGnT8KGb9m", "17Usm7uc58uLVrzoa2smh6iVXWzF4Wb1sd", "1MLHhX9Xy7wQDLddAyiVHdVR7ugvPt5p2n", "128JZsFtb7irTpKPZrveXYRtKGNPjshzeP", "16jxLgwhx8e71G8hAjXc8MMQKq3KwaFRDQ", "1BsGzAt8MM424BUyV5vkmoXWfKw5tcPDet", "1AaPzSZDmWHN6ZgkiJzQKsePqjVxvsYBhu", "1G7rSqbsVugpSeocHiZnR3mE47zdijxj9q", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "1qFKZDKRdAcjyTeB7GezEoToY4YwyM6xT", "366Dgw4pi3rnvu5zizVWZF6nijWxZWc6RA", "3D1Ks1nEVbbiYeU2yZvCiQA2mPhhUBvTk7", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1NHtBNqJ65hzmz7CcCnAuepSFGeVGzjpaA", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "19fAbPNubiPpFxGwwBuSigpDHJtJpoZD7B", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1Jmx7ngu4cWmLxrm9dVYofXXxc8BjFN9w3", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1Lvprx4Dhjq2yuKmHAuMwjxpz3JY3zKvgi", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1K5KUM94qGD1NHKPt1eXKmGGjuXdJJbocm", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "3L4Phz7ukztyxuNxkbTTf8qiwviPKcuUZH", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1PHonqk9w9aVbN9U4dNLN1v6T2fHGSngLe", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "18RQ4R248g31KMiCQphypmjHGkzgt9goCJ", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1MSTPByvfazzX7Vqc77U1oHRkCB6rseQMm", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1LJ9b9TogRxuYcnKJjnJGzstoGnnsWpYbm", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1Aume1s4UfSHaVgoFUFLoWzU5Y7DLPMkq3", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "12hKtA7QWTeuzaiPxEjxXagWJPC9FngZAr", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1AaeSySBC7Y7gA23F46axiNkpc6bzJgbac", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1Bf7dpEQoswzyWvwBGffn9QZyfK9K4rGXC", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "139gwSJRc5Bd1LpBt9Fgrsa87BjfEqKRHF", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1DQvkgUyCFKCMwu7u3pp77M4PApvfDhmEN", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1BN9KDp98nNGZ7nFbfJoh4kFgNLg6cxMj2", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "18p8bvoz1rMKD3puZPjguMWn9soQd5ev6E", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "18DmAs43MQcpm4ke7E6yAz4stXiDmJaDaB", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1BVAfq35Ri7nYF4i8eekYjzJKznEyQQaok", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "13jVvALMRzF3NYNcPF4L1Ji3DqssDGSD4S", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "3LU9osxB7TtB6bFphPuQVm4eJW5V7e8hVm", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1LDtopngfHFNthoqtP3oBx9iXk1uoJwRLQ", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "3LSfuYmmFXjp4D7aGdmt7HcfnNzmZAe9wf", "36FU6xWW8zKgVH99QHU5erxWKuF9hQE4No", "1GgGw478qTecCRbR9wFKZi65QcZMobmrWK", "39WAmsQwW4SMcBMTzVg9sU486AMGxaH678", "1ADTTNdpca4PLBahUBtt9tMotkfZSYm978", "1J2f6naEC4jZPcpr2NzAqvK1vTR2BvuCFe", "3FdA3PjdKFjHki2oDXTgNKy1a4fFv2QWnr", "1FcdSvHufCM3WG8YzaTo6jMf1efSBzAhtm", "3HFmbznq6Ddr9A1Ri2ryXkmRheW7xij3L8", "3AgXWCKLeRqm2p3tjADebv1wd7eKdnNm6e", "3Pfd4r6HipsdFxbBgvKKVTRkEzLYT2K1yQ", "33SoBRA6UoSVaTJbvaETN33g4Xh6AkJf1s", "35SfA6HM8jt6Nr49rJMougebrjni4twMjH", "328ac9t3cBuNDUzCJEr4mCSQyrrRqNxrXi", "3Pfd4r6HipsdFxbBgvKKVTRkEzLYT2K1yQ", "3Lkp51cpJS44mKfJDLCBWmB1wXqK9rsg9y", "36e7GYMxWM45RX1ahcWU6HoNDoq6dm9YZL", "1AVRk96qM3UtjvQFFxf6VGBvab2XYJvVA5", "3JnFBLxDCutY3bZEZsPTkHAaUA1bxmEMX2", "115wNdJY1par4ELiXJsvhZyHcc5Et9oki9", "3CD1QW6fjgTwKq3Pj97nty28WZAVkziNom", "3ARVhpo2mKVUPTJWDvkDmUeqQAmTnoa687", "1xM5Hbh8ssE96bfLay6XtRdjk74H87jWo", "1FNsTnDsTRnFrtfD7hfXVf2X6aCvAc744s", "1BgyYa8JNAaMf7Sdt89sb6A8CZMMyphN7Z", "189DGwpqygxDMNBcKuTWJBRT7a5tN2onv1", "1B9M1b8pfK645jcQBngZG49FJ6maQG583L", "3BFxxZL6arLbci5om7Ee6tcJ388TWAi7nf", "3FfE4fBEVFguxeEUHQpmC7Tpm71Foq2cYf", "1CUiv3eyNQDMq474GMHN2rESYH4PRVfHQD", "15d1Kyfroya95pQUCKCDp6jtGW18qZJvxS", "31z8z5A3sdDG5ny5REZ2ye5U98QjLRNsY7", "1JznybH6k3tj6BT8WPvwBwid4iCL6NzST8", "3JFxGXZtyNvvtAJvsEUy3VDj4r5HNzfA7k", "19vP1UgTfA77vqcN3G1Ds81M3L5omFRNbC", "1GtPHyEVNPu6QXt5Vu1xnEiaSPzRQNSnyT", "1GZxg2MXYWW4qiHGVzH7gfoN3HpiDAwUin", "1JAgvUHZgBAC6o28zWrnzcDKRuwwaTJykc", "1N8xnKQXVHbYzGUxVrvVzjRsHKpxpUzBRd", "1CSo8SmSMCoSZufT5F5AtWfhSkah72oMDt", "1PAeh5jyYi319iBz4EwAwYwBgE7dsXbzkZ", "1C167K8UB6scFWBkdMv2e1wMsdAszNkmNA", "12kVgAw31DGbCy9JPcAPQYqsZiVy1psvNe", "1NTSb1TZsSEsfeCST3tZX7fTYDZL6DTg3G", "1M7cK64Pbaq5y5r4EfjjcwV5fnyFNAdctS", "167p2NhRfXHsuRugyFWjR3YzYxr1vadkux", "1FyFtcB5ksuvjavm9kMv5WhkC6tse5VVxv", "1FKrGstkC3qRazkVmVA8ZLndrcG7t7qjGc", "1BjeP1yBTFLUFeaFJSRDi1Hh8VYshpQiy1", "1EY1bNaRmA7duDHoS5FFGR9w1YR4y2V8tH", "1MUNsQqjBtpuj5ABcnakyCXJve71NzWada", "1GyUC1RoL4nETGXvFkjNncRbr8QdRzCqSs", "1Gs8FbAcx3H8QtwCfkzhfRJEUWGcjinjnn", "1FLM9RvDgBpgyf3UNAkX9em8PjMrPegJrF", "18fuPaJEJCRNdtioDBASYJzjyNPCwSv1HD", "1ERQ87XMT4FAGD66sLtU8UWPRF32gxqSsX", "1EbezEhxhsKmQkdqGGn1XUzxMNEgkZK48u", "1FQkpdV44Ebu7eYMPtP2NswdsZKJJosuXF", "147vHvuM1RKBJpfzS7GchnjJeDeARnfNYh", "1JphuPaeT6Aa8HoGALVVQkDu4VYwvXSa1B", "1Ds47mF3VyxxFd8DcwW6LFDrtcuiDMagjK", "1EuXtuJRRC27Z3dakgrMgd5TxX9jFNSBG9", "1FPktxc7qu4JCDThhuSKc25oVY7tr61B8H", "1J24etcJGPm1NkMsXKzTKvbxTsh3JBegdB", "19RKw35bKuaLE3q1CLp9DsdWGGU4YMLXzi", "3CD1QW6fjgTwKq3Pj97nty28WZAVkziNom", "13K7L7vYqPfVHH5sszKqvpd7325985kZG2", "14X387U8qwzXf9AYbRB5KVbywkFMdLS8ux", "1F97wPj9kJ7aKMUiTxzVCSC8pM4NJemjDV", "19Uc46VtZQpA5ah3yMPjzDV1jrKucLCayL", "3JK7pu1RmJS4dcG1JfFSQgyiddkbiEsX1r", "1tpmBRvvJqwTZ3NBavY4mxWu9zJQ6GELm", "1D69mpKCvp9YCZrRkDjeXcfRY8eBVS1Byz", "145sL6X18G8JnYozeXZDKwC2dRygYkRS3d", "171oSrJPUwo1ycFznRvx4bh83RVBxLqo9N", "1N28MQnmy15y34C4ceWARHANqAVjVuQP4e", "1HkL7LYfobVGuhk8wu8kCPhbVFd4XDYAUx", "1EdEUGSpJCDmf7RAJCYwwXUQ2tKCk2waJe", "1LBisxpC4AxJ5GJUWEW7ZWbs52LTU7jZB6", "17fdDvchuUJ97knEAVTMmBg9R2kUaLGm5K", "3My1gfUk1gom4mLUSkGVskxX3Do52Um1SP", "1KMtoNmWWknXic2ge2QNpm3KVAwP8dwATb", "18B77PbxidDZ81brpXyMuz1LoNmGYdt2WU", "1JtfeU9ZAYp1gHXYFQWrYVkrQ1Y1P8Gx7X", "1DXopYDTRRi2nxyS7g2yxdHZRSQzgAE67Y", "1PcgFjG2rUEBor2ys7rtj2FT4geEDVEubT", "1JZwiDwAcsNRyWNVnPWhE7PvL3tH6waEji", "1Ef29vu3sEE2k4rnpvj92eyLy2spfAF5bw", "1FqtVkKapfaFVVHCY6kUpzBffc1LTtGUN", "3AkFf1dAjbdPgxVSvocJDVD97WidnZhTC5", "15TLEFek69WQSNowVDNRXbLLyBARPNk1vy", "13S3mUNzQ12RER2dMpK8CFtYVMks944JEm", "1ATDKFBNUCziY8Whz5YiEapJTF8XJVEfhD", "17WTYjo6EF7j51aP2H4SsH8yHXqtq4prvw", "12tAiui43gjbDgGhce4mi2n67nA175SHzq", "12pAsyMdZoTHPvkiRAZiuQhC8bF4DLbYpQ", "3Mu28CAbo65dwDxGDowVAdxKdqiBsEmhRG", "1HTtn8iaFCKDNZFaVyEf3pGjG8ng2cVuMJ", "1FnE116QKWHXBixUBphceJt895zPFcg16E", "1Mj9ox6rmvyRzx5f97ZjH5snornhWtR3fQ", "1BuLQJujtyvXNqL8mXeekBBGqPVaC7B3sY", "14GpyBZ1CoxLFVD9hvYHSanALYKpgMaSM5", "1NitX8uDjH369cJ646keKBpYbUQpzhkAH5", "1Ldk2q9NHB1bHuceUdgnzQQs8znDHEt9ck", "3GiUQcU1Tb4QX627VsM9yLuFE11tAZYcRE", "3CrGiBb5w5DW9tz1AdxiYS97gcmNctNPHM", "35SZaGi328gYj6WiWdam5ZdMvktL3YV9AR", "3JiVBide2KwB2DKkj4wu4PXsKpxrxWUgbF", "3JBu81xC2xFX64dskEYtTS7BuU7jXWmqAJ", "3F3Sg7QHiPH5Lgvy6UGtdnne8veZfY66aC", "37oyBeat6JYZveN8QuqhxAiV5fMFw6qofh", "38QU5MvnQhNHkQFKgch3jy2nbfEohwnq8T", "1L5soe6gaY2iaxQ7iXcqUxiMcS8VRG1bMe", "1BcoUPzbwY4ipzKRDZMNAddr8BxThCXon6"]

	context ".mk_pubkey_script" do

		context "given public key" do

			script = s.mk_pubkey_script addr

			it "converts it to scriptPubKey" do
				expect(script.length).to eql 50
			end

			it "converts to proper format" do
				expect(script[0..5]).to eql '76a914'
				expect(script[-4..-1]).to eql '88ac'
			end
		end
	end

	context ".mk_scripthash_script" do

		context "given script hash" do

			it "converts it to scriptPubKey" do
				script = s.mk_scripthash_script multi
				expect(script[0..3]).to eql 'a914'
				expect(script[-2..-1]).to eql '87'
			end
		end
	end

	context ".encode_op_n" do

		context "given input out of range" do

			it "raises error" do
				expect{s.encode_op_n -1}.to raise_error ArgumentError
				expect{s.encode_op_n 17}.to raise_error ArgumentError
			end
		end

		context "given zero" do

			it "returns '0'" do
				n = s.encode_op_n 0
				expect(n).to eql '0'
			end
		end

		context "given input between 1 and 16" do

			it "converts it to op_n" do
				1.upto 16 do |i|
					expect((s.encode_op_n i).to_i 16).to eql 80 + i
				end
			end
		end
	end

	context ".mk_psh_redeem_script" do

		pk1 = "04a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575fa349b5694ed3155b136f09e63975a1700c9f4d4df849323dac06cf3bd6458cd"
		pk2 = "046ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640de68c2fe913d363a51154a0c62d7adea1b822d05035077418267b1a1379790187"
		pk3 = "0411ffd36c70776538d079fbae117dc38effafb33304af83ce4894589747aee1ef992f63280567f52f5ba870678b4ab4ff6c8ea600bd217870a8b4f1f09f3a8e83"

		context "given zero keys" do

			it "raises error" do
				expect{s.mk_psh_redeem_script(0, [])}. to raise_error ArgumentError
			end
		end

		context "given incorrect number of keys" do

			it "raises error" do
				expect{s.mk_psh_redeem_script(3, [])}. to raise_error ArgumentError
			end
		end

		context "given too many keys" do

			it "raises error" do
				expect{s.mk_psh_redeem_script(3, Array.new(17) { |i| i })}. to raise_error ArgumentError
			end
		end

		context "given a pubkey" do
			
			it "encodes to redeem script" do
				res = s.mk_psh_redeem_script(1, [pk1])
				expect(res[0..1]).to eql '51'
				expect(res[2..3]).to eql '41'
				expect(res[4..133]).to eql pk1
				expect(res[134..135]).to eql '51'
				expect(res[136..137]).to eql 'ae'
			end
		end

		context "given m-of-n pubkeys" do
			
			it "encodes to redeem script" do
				res = s.mk_psh_redeem_script(2, [pk1, pk2, pk3])
				expect(res[0..1]).to eql '52'
				expect(res[2..3]).to eql '41'
				expect(res[4..133]).to eql pk3
				expect(res[134..135]).to eql '41'
				expect(res[136..265]).to eql pk2
				expect(res[266..267]).to eql '41'
				expect(res[268..397]).to eql pk1
				expect(res[398..399]).to eql '53'
				expect(res[-2..-1]).to eql 'ae'
			end
		end
	end

	context ".address_to_script" do

		context "given address" do

			it "converts it to scriptPubKey" do
				script = s.address_to_script addr
				expect(script[0..5]).to eql '76a914'
				expect(script[-4..-1]).to eql '88ac'
			end
		end

		context "given multisig address" do
			
			it "converts it to scriptPubKey" do
				script = s.address_to_script multi
				expect(script[0..3]).to eql 'a914'
				expect(script[-2..-1]).to eql '87'
			end
		end

		context "given testnet address" do

			it "converts it to scriptPubKey" do
				script = s.address_to_script test
				expect(script[0..3]).to eql 'a914'
				expect(script[-2..-1]).to eql '87'
			end
		end

		context "given address" do

			it "returns scripts" do
				0.upto addrs.size - 1 do |i|
					scr = s.address_to_script addrs[i]
					expect(scr).to eql scripts[i]
				end
			end
		end
	end

	context ".script_to_address" do

		context "given pubkey script" do

			it "converts it to address" do
				script = s.address_to_script addr
				result = s.script_to_address script
				expect(result).to eql addr
			end
		end

		context "given multisig script" do

			it "converts it to multi-address" do
				script = s.address_to_script multi
				result = s.script_to_address script
				expect(result).to eql multi
			end
		end

		context "given testnet script" do

			it "returns testnet address" do
				script = s.address_to_script multi
				result = s.script_to_address(script, 111)
				expect(result).to eql test
			end
		end

		context "given scripts" do

			it "returns correct addresses" do
				0.upto scripts.size - 1 do |i|
					adr = s.script_to_address scripts[i]
					expect(adr).to eql addrs[i]
				end
			end
		end
	end
end