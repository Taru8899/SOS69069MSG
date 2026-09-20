import traceback


def _run():
    try:
        from sos69069_msg.app import main
        return main()
    except Exception:
        # import-time failure (e.g. a missing dependency): show it on screen instead of closing
        import toga
        from toga.style import Pack
        from toga.style.pack import COLUMN
        text = traceback.format_exc()

        class ErrorApp(toga.App):
            def startup(self):
                self.main_window = toga.MainWindow(title="sos69069 msg - error")
                self.main_window.content = toga.Box(style=Pack(direction=COLUMN), children=[
                    toga.Label("sos69069 msg failed to load. Screenshot this and send it:"),
                    toga.MultilineTextInput(readonly=True, value=text, style=Pack(flex=1)),
                ])
                self.main_window.show()

        return ErrorApp("sos69069 msg", "org.sos69069.msg")


if __name__ == "__main__":
    _run().main_loop()
