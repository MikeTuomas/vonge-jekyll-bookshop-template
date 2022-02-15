---
date: 2022-02-11 22:22:52
title: Tämä portfoliosivusto
description: Portfoliosivuston luominen portfoliossa, no miksei?
tags:
  - Web Design
  - Web Dev
image: /uploads/screenshot-2022-02-11-at-23-34-51-vonge.png
---
Tuntui aika hassulta lisätä tähän projektiin tägejä. En koe tätä sivusto muotoilleeni tai devanneeni kovinkaan paljon, mutta jotain kuitenkin.

Muotoilun lähtökohtana oli löytää about fiksulta vaikuttava pohja sellaisella teknologia stackillä, että pystyn sitä muokkaamaan järkevällä vaivannäöllä. Loppu muotoilu mukaili pitkälti kivenveistoa: "Poista sivustosta kaikki mikä ei kuulu&nbsp; portfoliosivustoon, mutta ei yhtään enempää". Devaus oli luonnollisesti muotoilun toteuttamista. Tässä projektissa kehitystiimin erimielisyydet pysyivät jotakuinkin aisoissa ja onnistuin välttymään pahimmilta kommunikaatiohäröiltä.

Kuitenkin sivu on ylhäällä internetissä ihan mukiin menevänä, mistä minusta voin olla ylpeä. Käyn läpi tässä artikkelissa asiat, jotka tein tätä sivustoa luodessa. Let's go\!

## Ihan ensiksi

Rehellisyyden nimissä tätä projektia olen pyöritellyt päässä ainakin yli puoli vuotta ja muutaman kerran aihioita luonutkin. Oma portfoliosivusto on minusta tosi cool juttu, joten totta kai sellainen täytyy luoda\! Mutta tämä sivusto on parin viikon aikana luotu tyhjistä niin paljon kuin tyhjistä nyt kukaan voi mitään ikinä luoda. Eli vuosikausien harrastelun pohjilta parissa viikossa pystyyn nostettu sivusto.

## Cloudcannon CMS

Cloudcannon valikoitui alustaksi melko sattumalta. Tykkään Jamstackista tosi paljon ja olen sillä laittanut sivustoja pystyyn jo aikaisemmin harrastusmielessä. Suurimpana syynä on, että Jamstackilla on naurettavan helppo saada sivusto ylös ja static-site-generaattorien kanssa sivustoista tulee kivan nopeita, melko helppoja koodailla ja lopputuloksenkin saa näyttämään kivalta. Mutta perus git+netlify combolla sisällönhallinta tuntuu aika nihkeältä. Siksi olen kokeillut paria eri CMS palvelua, joista aikaisemmat tuntuivat tavalla tai toisella myös aika nihkeiltä. Cloudcannon on nyt viimeisin testissä oleva.

Valintaa auttoi myös paljon se, että Cloudcannonilla löytyi suoraan hyvä template sivustolle ja pääsin helposti kärryille heidän bookshop frameworkistä. Bookshopilla luodaan komponentteja, joita voi kerran luotuaan lisäillä graafisesta käyttöliittymästä eri sivuille.

## No mitäs tuli tehtyä?

Kerran sivusto on pitkälti vain muokattu template, niin kysymys tietenkin kuuluu, mitä muutoksia on tehty ja miksi?

### Sivuston rakenne

Sivustolla täytyy tietysti olla rakenne elikkä sivusto-kartta. Perus portfoliosivusto ei minusta kaipaa mitään muuta kuin itse portfolioon kuuluvat projektit, niiden esittely, vähän kuvausta portfolion omistajasta ja linkit sosiaalisiin medioihin. Tällä sivustolla tarinoinnit minusta ovat omalla sivullaa, mutta senkin voisi periaatteessa jättää pois ja liittää etusivulle. Vaikkapa projektien jälkeen

### Oma copy suomeksi

Itsestään selvät alkuun. Muutin kaikki tekstit suomeksi formeissa, navissa ja niin edespäin. Sitten haastavampi osuus oli keksiä tekstit nappeihin, etusivun "hero" osioon ja yhteydenotto lomakkeeseen.

### Blogikortista tekstin kirjottajan nimi pois

![](/uploads/yhdistetty-author.png){: width="880" height="597"}

On hyvin selvää kuka tekstit on kirjoittanut minun portfoliosivustolla. Muutos onnistui poistamalla koodia bookshop komponentista.

### "View all" nappula pois

![](/uploads/view-all.PNG){: width="768" height="175"}

Minun mielestä portfoliossa ei pitäisi olla niin paljon projekteja, että niille tulisi luoda erillinen sivu, joten "view all" nappula on turha. Muutos onnisuti poistamalla koodia bookshop komponentista.

### Ikonipaketin päivitys

Halusin lisätä linkin Gitlab profiiliini, koska siellä on useampi kuin kaksi vihreää täplää, mutta valitsemani template ei ladannutkaan gitlabille ikonia ollenkaan\! Aikani ihmeteltyäni huomasin ikonipaketin, jonka avulla kaikki ikonit sivustolle ladataaan, olevan 2 iso versiota jäljessä (4.5.0-&gt;6.0.1).

Paketin päivittäminen muutti kuinka sitä tuli käyttää, joten minun piti päivittää kaikki ikoneihin liittyvä koodi.

Päivityksen lopputuloksena Gitlabille löytyi ikoni ja kaikki ikonit ovat hieman ylhäällä keskilinjasta. Jääköön toistaiseksi ominaisuudeksi.

&nbsp;
