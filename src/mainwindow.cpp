#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->file_select, SIGNAL(released()), this, SLOT(handle_select_file()));
    connect(ui->start, SIGNAL(released()), this, SLOT(handle_reassemble()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::handle_select_file() {
    QString path = QFileDialog::getOpenFileName(this, "Open", ".", "*.pcap");
    ui->input_path->setText(path);

    std::string p = path.toStdString();
    int i;
    for (i = p.size() - 1; i >=0; i--) {
        if (p[i] == '/') break;
    }
    QString substr = path.left(i + 1);
    ui->output_path->setText(substr);
}

void MainWindow::handle_reassemble() {
    int err = re.analyze_pcap_file(ui->input_path->text().toStdString(), ui->output_path->text().toStdString());
}
