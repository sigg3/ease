from pathlib import Path

# Translations
import gettext
_ = gettext.gettext


class Settings():
    # Name/Logo and Window Title
    # leave as-is, do not translate
    name = "EASE"
    title = "EASE: Encrypt And Send with EASE"

    # Some defaults
    git = "https://github.com/sigg3/ease"
    # homepage = "https://ease.sigg3.net"
    # relay  = ""
    crypt_buffer = 64 * 1024
    language = "en"
    archive = False
    use_tar = True
    compression = False # default: use store (no compression)

    # PySimpleGUIQt template
    guitheme = "SystemDefaultForReal"

    def __init__(self, **kwargs):
        # set key-value entries
        self.__dict__.update(kwargs)

         # Set "home" dir (our default)
        if Path.home().is_dir():
            self.home_dir = Path.home()
        else:
            self.home_dir = Path.cwd()

        # Set current homedir to output dir (default)
        self.output_dir = self.home_dir

        # thread dict for _this_ object
        self.thread = {}

        # temporary files (for removal)
        self.wastebin = []

        # base64 encoded PNG icons dict
        self.icon = self.populate_icons()

        # file sending services dict
        self.sites = self.populate_transmitters()
    

    def clean_up(self):
        for xfile in self.wastebin:
            try:
                Path(xfile).unlink(missing_ok=True)
            except Exception as e:
                print(f"Could not remove temp: {xfile}")
        self.wastebin.clear()



    def populate_transmitters(self) -> dict:
        """
        Returns dict of online file transfer sites (for sending over WWW).
        Separated into its own function for maintenance reasons.
        Use _('string encapsulation') for strings that should be translated.

        Each entry must contain:
        - short name (e.g. URL without protocol)
        - URL (preferably https)
        - date (changed/updated/added)
        - file expire (in days)
        - max file size for any single file in GB
        - require login (bool)
        - known limitations (short string)
        - working URL to faq or help page (used for reference)
        - automation enabled (bool)

        Automation disabled at the time of writing.
        Setting automated to True entails writing and linking a function
        that accepts .aes input file and sends it across the desired site
        (using e.g. selenium) and returning the URL created to the end-user.

        Use _('string encapsulation') for strings that should be translated.
        """

        # setup return
        sites = {}

        # sendgb.com (added 2020-09-07)
        name = "sendgb.com"
        sites[name] = {}
        sites[name]["changed"] = "2020-09-07"
        sites[name]["site_url"] = f"https://www.{name}"
        sites[name]["days_expire"] = "7"
        sites[name]["max_size_gb"] = "5 GB"
        sites[name]["require_login"] = False
        sites[name]["automated"] = False
        sites[name]["limitations"] = _("files stored for 90 days.")
        sites[name]["faq"] = "https://www.sendgb.com/en/faq.html"

        # sendgb.com (added 2020-09-07)
        name = "fromsmash.com"
        sites[name] = {}
        sites[name]["changed"] = "2020-09-07"
        sites[name]["site_url"] = f"https://{name}"
        sites[name]["days_expire"] = "14"
        sites[name]["max_size_gb"] = _("None")
        sites[name]["require_login"] = False
        sites[name]["automated"] = False
        sites[name]["limitations"] = _("files 0-2 GB in size must queue.")
        sites[name]["faq"] = "https://faq.fromsmash.com/"

        # sendgb.com (added 2020-09-07)
        name = "surgesend.com"
        sites[name] = {}
        sites[name]["changed"] = "2020-09-07"
        sites[name]["site_url"] = f"https://{name}"
        sites[name]["days_expire"] = "7"
        sites[name]["max_size_gb"] = "3 GB"
        sites[name]["require_login"] = False
        sites[name]["automated"] = False
        sites[name]["limitations"] = _("store up to 5GB per month")
        sites[name]["faq"] = "https://surgesend.com/help"

        # dropbox (added 2020-09-08)
        name = "dropbox.com"
        sites[name] = {}
        sites[name]["changed"] = "2020-09-08"
        sites[name]["site_url"] = f"https://{name}"
        sites[name]["days_expire"] = "N/A"
        sites[name]["max_size_gb"] = "2 GB"
        sites[name]["require_login"] = True
        sites[name]["automated"] = False
        sites[name]["limitations"] = _("free account gives 2GB storage total")
        sites[name]["faq"] = "https://www.dropbox.com/basic"

        # add-more-here (date added)
        # name = "tld.tld"
        # sites[name]["changed"] = "date added"
        # sites[name]["site_url"] = f"https://{name}"
        # sites[name]["days_expire"] = "N/A"
        # sites[name]["max_size_gb"] = "X GB"
        # sites[name]["require_login"] = True
        # sites[name]["automated"] = False
        # sites[name]["limitations"] = _("small note on limitations")
        # sites[name]["faq"] = "<url to faq>"

        # return any hits
        return sites

    def populate_icons(self) -> dict:
        """ base64 encoded PNGs go here """
        a = {}

        # Icons8 icon file (MIT) Copyright (C) The author(s)
        a["icon_decrypt"] = b'iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAB\
                            HNCSVQICAgIfAhkiAAAAAlwSFlzAAAOxAAADsQBlSsOGwAAABl0\
                            RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAJzSUR\
                            BVGiB7ZjPahNRFIe/M23FIqigIFSrG0EjutCd6E43voALwWTQPI\
                            C7FHURV40IXQpW2yRSH8AX6Er6Aq3WCi4sVlyIGEQQbea4aNQoy\
                            cy5M7dJF/Ntsri/8+eXm3tmbiAnJxOSJVifcIxRTqOcAU4iTACH\
                            gYPAGLCvI20BP4FPwAawgbKGsMwmK1Lm3cAMaJPLKLeAi10NZqU\
                            FvCBiRm6w6BLoZECbTKNUXONcSgA1CbltDTA3onVChHqqtlwRQi\
                            nRtEgDi0gVQbiTrSsHlLuqti/XJNKnFIh4FSN5hrKIsAZ8ZIzPt\
                            PkhRb514vcwwi4iDtDmEMoJAi6hXOubMeCUFFn1Y6BJGeVx3yRh\
                            ujOhDTRmuSwhc0k5TD8h4LxR5xNTTZsBpRC7vMARU57umHkmYwU\
                            SX/M31h04Gru6yWxiQ13oPJMEzMaLEmp2GDXW3J+wfoWAdW0Ys/\
                            mpCdh3YHeGRtIybhFZDXzP0EhaTDWtBr5kaCQtXy0iq4H1DI2kQ\
                            21vqDYDkvxE9E7AG5vMgrKUqZk0RLaaNgPBEAwYa9oMXOc18DZL\
                            P468Z5yXFqHJgAgKTGdqyY2aXKVtEVqnEBIyh/AAYt8gfTBLiYd\
                            WsfuduMEF4CZbd+LjaXL0oAUsITySEs9dArP9K7HAXiLOEnEOmH\
                            EKFqaIWGaEFSmmf854u5z3upysftj6LEz0KJzyEvQ/5jOwU8kNp\
                            EKo+ko1eANCVUrc85Vu8AYi20XFyjB2oKJ1ar7SDesMVHylyqdQ\
                            KvIp9Jd8CjmTT6F/yafQH4QpB23VV1lvBqTEfZOJnTyFEk14bh6\
                            24Qz0NbENzefkeOAXZUqTVtznmewAAAAASUVORK5CYII='

        # Icons8 icon file (MIT) Copyright (C) The author(s)
        a["icon_encrypt"] = b'iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAB\
                            HNCSVQICAgIfAhkiAAAAAlwSFlzAAAOxAAADsQBlSsOGwAAABl0\
                            RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAKNSUR\
                            BVGiB7Zi/a1NRFMc/9/ZVA43kkW62LoVOgiJPUQeHB4EOounm2P\
                            +horZbp4IIOthFXHURBwtujX35B6IU1MEKhWLApSWpdqg19zg0w\
                            TSEvJf3I7H4PlPu5Zx7vt+8c96FBykp/zcqzsMcxxm1bbtojJlV\
                            SjnAOUCAbyJS0Vq/qdVqq5VK5TCumrEZcF23qJR6BEz7hG6KyD3\
                            P81bjqDsS9YClpSWttV5WSq0A4wFSxpVSd6ampk7Pzc155XJZot\
                            SPbEBrvQws9JmmgBvb29untra23kWqHyXZdd0i8KBj+wB4KiLXL\
                            MvKWpaVNcZcB1aAX+2BIrLguu7tKBpCz4DjOKO5XO4Tx3u+KiI3\
                            Pc/b6JZTKBQuGWPeAmfbtjfr9fr5sIMd+gnYtl3kuPiDXuIBSqX\
                            SB+AWx5/EdPOsUIQ2YIyZbV8rpZ71Et9ifX39vYg8b98TkcEbUE\
                            pd7hDxMmiuiLzo2LoSVkeUIZ5oXxhjPveR+7HXWf0QxUC2fVEul\
                            38GTewSm+0aGIBIr9F/gdTAsAl0kclDJn+P8ASYAc4kK4kfwFrD\
                            sJC5z6ZfsK+BpvgNIB+Huj7YtTQX1DzVXkG+LdT85wctHiB/aHj\
                            sFxRkBmZiEBMKFaB2EANJ93wvcn4BJ/4tlBoYNqmBYWMlcagA1R\
                            rs7B/dlPkxmLBj/gjVJBED1Rp83/u7bv2etOOvlUgL7ewH24uDR\
                            Ax0a5Uk2gcSMpAfC7YXB4nMwESz13ebbdMa4iRIxIDiaGCTGNpO\
                            Tvw9kBoYNqmBYRPEwJ5/SGLU/QKCGCjFICQsa34BvgYaikVgJxY\
                            5/bHb0Cz6BfkayNzli6W5KPCKwbTTHvC6obmamefrAOqlpJxo/g\
                            B9k7aRwlhAgwAAAABJRU5ErkJggg=='

        # Icons8 icon file (MIT) Copyright (C) The author(s)
        a["icon_sendenc"] = b'iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAB\
                            HNCSVQICAgIfAhkiAAAAAlwSFlzAAAOxAAADsQBlSsOGwAAABl0\
                            RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAPCSUR\
                            BVGiB7ZhtaFtlFMd/z81LbaYZ7CUz6QzVabtZZju6UVb30oo6lI\
                            E6kIEw6AcHm3WgHwTnh4E4QSx0qAzpt8HQwVDRL1q26Wjt3Fbas\
                            jKtbeek617SJa3SG5YtL72PH9LEJrkzyU1sU7i/T/ee57n/c849\
                            51y4D5iYmJiYmCxixNF3+uU8+QoiOW0Ryrv72jZcKZaoUiyhHHg\
                            Iwa4Y8sLnb1+qKJaoSDcc2t1dUEVWeZfk4vVk68f1uwvxk2A+K/\
                            Avkh3FkrKmG3J6g4WztFhC1nkc4hRkV9mLQAewOsvWMTT2i+Zwp\
                            97iwrRQnFyCB6hE4Wv5s61Wb7HgITbacm/sbExeH/jmBUYCKzL2\
                            2CwzvLXtAs9V/QkwRtS+UTwbnJq7ZyErkEQveIDojIUjXZsZvLU\
                            KoBJr5JiUqTEv1BDnTExT+OBUE5/u+h6PM7iTbvt7EDmcWF+wIc\
                            4HNWznUGczn7zcyRJ75H15tqwvMdQl0UK5MP73Uj48sxVNCgVFf\
                            CG7HngUDAxxsVps7hA/37En5+derfuNvQ0DAJewhRsXTQUSfHt5\
                            beKyjmjZRyUxxNWuSUb8+l+idKIzlrm3r5fEEH/2yg8p9zOawvH\
                            +9Xw58FS2Rx0l2UIWRaNl0yAtmwaxKFrK2jrXZMp91iH+v1pq7h\
                            AXQklWIB9KYogLYdFXYNEnkNFCuXBdHWYocJGpuz4Alpe7qVm5m\
                            dXOqoID6h51caK3kmFf/KdtnXua1xrG2PKEX3e/XgIq4Lyfg4GJ\
                            H/nVfy7FdvvONW7fucZ61xY2PPyM4eCPnq3i+PnHUv2NL2NgfBk\
                            tjVfZ15RxGjOd2UKSM/dzcF0dTgZvs9nweL14vF6s1vh7uOzv4Y\
                            Zq7Mine9SVDF5P+9gva+i54kqP9XRGAlKzHASm0u0AQ4GLSQf1j\
                            duorqmluqaWjU9vTzoamjxvKIETvZVZtRN74oi/kBzMSODN9rpR\
                            JWapRXCSeDslmboX73mXu4JyhyNpL3c4cHk88T2hW4YSGJ5wZtX\
                            +3ecEUJF8hSYbRHP4D90h3n+k7iaQcfDUsOOlIPCgRMt4Rs6aol\
                            pEbW2rz3ps0tqWrm3Nqh2KWFWxPZyine9ntA8g4PNxNxRKGu+FQ\
                            gQmZt+8EH15ahaknddnVEjapaApGo3Sd64Llzt+xOn33SQWiwEg\
                            pdZuJHqj2pZ0w39x4+rI6COPr7UDWzVNI6hOE1Sn0bTZGktxuPf\
                            Udx1GEjCqnVcCs45+qljzZL8Q0g2sBCII0SORB4wGPx/aJiYmJi\
                            a6/AORnX+gBEwubAAAAABJRU5ErkJggg=='

        # Icons8 icon file (MIT) Copyright (C) The author(s)
        a["icon_easehlp"] = b'iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAB\
                            HNCSVQICAgIfAhkiAAAAAlwSFlzAAAOxAAADsQBlSsOGwAAABl0\
                            RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAGpSUR\
                            BVGiB7ZY9SwNBEIbfTS5GvLNQm4CiEFJpQLTTwo9eW5uonYYg/o\
                            FUscgfCEhAS7WxFfukSRcsJK34AcbCSi8haC5jJyh78YiZ3C3sU\
                            84sO+/DLncLaDQajZ+Ibs1EgaKOYe8DIgUgCZA5oFgNgG4hcDEy\
                            YZ3UtsSH60q3xlSxORkh5xrAPEtG79y0ndDG06H5LGuGZMVEgaI\
                            BCQ8ACxGjczV3SUOyplSgHbHTCEZ4AAARFpuv9p6sJxUQJFK8kX\
                            piW1aUCgA0y5mkR5KyoosALMYgvSLN5Cbwb9ZnDFR2TVR2TKxNh\
                            7nG8AnkV6KImQIxSyC/Osw1hk9gULAJZMstvNiEuk3IlltcY2Bw\
                            bVx6dLB81uDa/ht9hfyG7QrdZX5+tuNFm2WO8iegBfxGC/iNFvA\
                            bLeA3yguwPSW4ng6/Uf4EtMAAeZMV1REg1GRlZQQEcC6rqyJQHT\
                            OsU1lDBYFqJxzarKbFp6wZVAGbgIogHIyHraWHtFl3W+j5R0YCu\
                            fvM6FF/8vUPTycQ1PCAB4Eghwf+EAh6eKCLgArhXYkfv+f8zqBR\
                            hS9jd2TmUiJFJAAAAABJRU5ErkJggg=='

        # Smaller button (also Icons8, MIT). Currently not in use
        a["icon_globe"] = b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHN\
                          CSVQICAgIfAhkiAAAAAlwSFlzAAAHYgAAB2IBOHqZ2wAAABl0RVh0\
                          U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAQ+SURBVEiJt\
                          ZVbbFRFGMd/M+fsObttactC3S0WBGyRO0EMhAQDlYsoEdRUI0Z80G\
                          h86YNcTNCXvhgDJkQl8UEe8EGjiVwUAgiUKqCEIHIpl2JLsY1N24W\
                          ml6XbPXv2nDM+tD3udkvSmPB/mvlm5v+b831zZuAhS4xp1tba+Zpk\
                          nhJEAIQi5gpVz47V1/4/oOZwnm6ZW3ThVtueUQJgSluZAYuEXYCrp\
                          DD09F3H0XY7IWsXNS8MjB2wrW65EUgfcFw9nBleW36MJ6OX8JQklo\
                          hwoKGKvlQhuuZ0267+EjtWnhlpJUcGAttPbdI0t055MhzNjxHJj4F\
                          QANTeWT24SHgUmnEG0nkAOK4e1lF1ge2nNo3000fu3FPu1wsjV+SK\
                          qb8S1JMA3O4u54eGVzE1GwDbM/jprxdJezq6TPPyzIPcGyjRTres2\
                          Mu22hY+XXU29wtqDucZgfSBinCTXPv4zwT1JPWxBey59A6diShBPU\
                          VIH6A3Vcw3V9+kpXcqAM9MraM83MTSsnNMG39bM3TnIO+fC+UAdMv\
                          cIvCK11UcAaFIpPM43rwWxzPouB/FSgfpsibw1Z/v0pmI+Pvy0Pz2\
                          hicOY2h2sWEmNucChFv9VOlFGRpKi1IaC6KXeWvhHl6ZvY+lk38HJ\
                          XC8gG+YHxhgSlGL3w/qSRZP+kOT0q3OBmytnW97RklFuMmfXGDcZ8\
                          30E37eh8GZem3Od0TzY1mx2SXXsd1AhA9/mQtDRdY0OVcKV5UWdGQ\
                          dW8/TaOyu4EbXHBq7ZmYZLZv8G5GCzhxocbCPoGa5KS84z4XrOoAS\
                          XmlxsEdp0s0C/Ni4gVtds3JMEIp5j9TnxoeUbySEZZmTIKMGvVax7\
                          LWKSLkGhxrX09r3GHd6po9qMCPcyPhQzwMBUnigUD5AINpdpbH/Vh\
                          U9ycGf90TzGmzXHNVg2ZSzo8aHlXRCnoB2H+AKdRUg1h/l+xsbCQW\
                          SlBZ0MnNiAzMmNGLqqSwDx9NzTIfVZxXRb+frrqR+cPNDCn10rD3l\
                          GKXD/VXTTrL40QsAtMXL+Pb6G7ie5qegKNhH2bh/WFd+FCldH3C6d\
                          TkXOxZ3JD9+LrsGaU/7LHMn9+1Cv11W2MZ7i77k6SmDd5mnJD3J8V\
                          y7O5+/e/+rUywR4UL7Ei/Tywc4ZuALQ7PvDfebe8oHqzSkIjPOgui\
                          VnJQ0dZcDYDkh9t+sQii6nH7n8xwANZWW5QTXS+E5AF0DE2jtnZZl\
                          dvPunBzA7e4KUq7BvoYq4nahY7nmBnY/7xct+7reWXleIl8fhrTFy\
                          /yhM63LqWtZmQOI2+PYe/lt2uJljhT6RnZWns8cH/3B2V63JIh9SA\
                          k1cVHpJVlk9nG8+dlRpwIYmhOzHH09O1deGDn24Cez+qipFwSqA9L\
                          ZnHm6MmXqdkfa03c5/endmWkZGyBTH5ycpQltof/oozpdIS/zSeWt\
                          Ma1/mPoXMhSlLR8VmrIAAAAASUVORK5CYII='

        # Smaller button (also Icons8, MIT). Currently not in use
        a["icon_trans"] = b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHN\
                          CSVQICAgIfAhkiAAAAAlwSFlzAAAHYgAAB2IBOHqZ2wAAABl0RVh0\
                          U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAJrSURBVEiJ7\
                          ZPfS1NhGMc/75mejVJXdBFGWWkGmkY0ZbD8gTDKyAu7MPsHXKDhRV\
                          DdhRddmBYoIhFFRXijXgQhdKEUiporFkFqgknG0row2nTkznTn7WJ\
                          uOnUb7qYbv3A4D8/zfb/f5znPeWEX/xui85arCUBIcW49y0C8Q1Jn\
                          IaildzV25GqJDFLCwZJXs2/I2zcT08zqhrbAYPRWAjWJDEQ4uOd4J\
                          +MRowwACYHrrRZjIoOUzpuuuMJxOlPloDoCwhZdkU70gF1U4FvjhX\
                          Cndmhbo4NZe2Oa1FfZePk5j4ejRQAYFJ3GEicX82a6Rbn/amiCtSW\
                          T1Bzg01IjcVBX6Bi2kpnhq5VDv8ZEmdamRIjeQNSTLFZ1hbv95cx7\
                          0u/LQVOZ0tBiaWposTQlK5hu2trMoqby5utxA8hnSS85jOqCKaoLp\
                          pBS0OUqpOvjaaQUpBkDANlblhxvqZtRX2VLyIlctJ0I7wQpsQqBoJ\
                          9ZzyQAx/adQjXEv1Of3Pv5Mm8m75CXM0f+bGcgf4A4HBbvm37MqsE\
                          PwMTCMJdOXItp0v3hKG0D+aRlmPEterlhn6Sm+DuAO/KbCl1xAG6A\
                          b55xVg1+rKUVWEsrWBEas56JmN2/GM3hZH4hRbZScvMLeD6aA+BGx\
                          xGZoP7B2ddAFoD1fLXDtMf0KOQcqjvn+uran9Y92Sjc0Bp6Wy+o8w\
                          eQmeH8b586J8q1rE2faB1agB6Uv7edQ2+zAZb9yzPBoNobawIhaJ6\
                          eHG//6XbjW/JKKWRzpBbrkMVeY041aFcAVoLGHtdArzcWF8BaeblE\
                          6nqxIuX7sf5XI/G4u4jCP1lX4BBIAojvAAAAAElFTkSuQmCC'
        # return to world
        return a
