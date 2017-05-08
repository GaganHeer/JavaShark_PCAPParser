package PCAP_GUI;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.jnetpcap.util.PcapPacketArrayList;
import PCAP_GUI.TableInfo.TimeTable;
import PCAP_GUI.TableInfo.UsageTable;

import java.io.File;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Gagan Heer
 * Renzo Pamplona
 * Rodney Tran
 */
public class Controller implements Initializable{

    @FXML
    private MenuItem openItem;
    @FXML
    private Button usageBut;
    @FXML
    private Button timeBut;
    @FXML
    private Button dataBut;
    @FXML
    private MenuItem packetGraphBut;
    @FXML
    private MenuItem timeGraphBut;
    @FXML
    private MenuItem dataGraphBut;
    @FXML
    private Label unloaded;
    @FXML
    private Label loaded;
    @FXML
    private VBox packetBox;
    @FXML
    private VBox timeBox;
    @FXML
    private VBox dataBox;
    @FXML
    private TableView<UsageTable> packetView;
    @FXML
    private TableColumn<UsageTable, String> packetIPCol;
    @FXML
    private TableColumn<UsageTable, Integer> packetCountCol;
    @FXML
    private TableView<TimeTable> timeView;
    @FXML
    private TableColumn<TimeTable, String> timeIPCol;
    @FXML
    private TableColumn<TimeTable, String> timeFirstCol;
    @FXML
    private TableColumn<TimeTable, String> timeLastCol;
    @FXML
    private TableView<UsageTable> dataView;
    @FXML
    private TableColumn<UsageTable, String> dataIPCol;
    @FXML
    private TableColumn<UsageTable, Integer> dataSizeCol;
    @FXML
    private VBox packetGraphBox;
    @FXML
    private BarChart<String, Integer> packetGraph;
    @FXML
    private VBox timeGraphBox;
    @FXML
    private BarChart<String, Long> timeGraph;
    @FXML
    private VBox dataGraphBox;
    @FXML
    private BarChart<String, Integer> dataGraph;

    private ObservableList<UsageTable> packetData = FXCollections.observableArrayList();
    private ObservableList<TimeTable> timeData = FXCollections.observableArrayList();
    private ObservableList<UsageTable> dataData = FXCollections.observableArrayList();
    private String fileName = "";
    private PcapModel pcap = null;
    private PcapPacketArrayList pcapList = null;

    //from stackoverflow
    public static <K, V extends Comparable<? super V>> Map<K, V> sortByValue(Map<K, V> map) {
        return map.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByValue(Collections.reverseOrder()))
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (e1, e2) -> e1,
                        LinkedHashMap::new
                ));
    }

    private void noFileError() {
        Alert noFile = new Alert(Alert.AlertType.ERROR, "Please select a PCAP File \n File -> Open");
        noFile.show();
    }

    public void handleButtonAction(ActionEvent event) throws Exception {
        if (event.getSource() == openItem) {
            final FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Open File");
            File file = fileChooser.showOpenDialog(new Stage());
            unloaded.setVisible(false);
            loaded.setVisible(true);
            if (file != null) {
                fileName = file.toString();
                pcap = new PcapModel(fileName);
                pcapList = pcap.parseFiles();
            }
        } else if (event.getSource() == usageBut) {
            if (pcapList != null) {
                loaded.setVisible(false);
                packetBox.setVisible(true);
                timeBox.setVisible(false);
                dataBox.setVisible(false);
                packetGraphBox.setVisible(false);
                timeGraphBox.setVisible(false);
                dataGraphBox.setVisible(false);

                Map<String, Integer> packetCount = pcap.createPacketCount(pcapList);
                Set<String> keys = packetCount.keySet();
                for (String tempKey : keys) {
                    packetData.add(new UsageTable(tempKey, packetCount.get(tempKey)));
                }

                packetIPCol.setCellValueFactory(new PropertyValueFactory<>("IPaddressProperty"));
                packetCountCol.setCellValueFactory(new PropertyValueFactory<>("packetProperty"));
                packetView.setItems(packetData);
            } else {
                noFileError();
            }
        } else if (event.getSource() == timeBut) {
            if (pcapList != null) {
                loaded.setVisible(false);
                packetBox.setVisible(false);
                timeBox.setVisible(true);
                dataBox.setVisible(false);
                packetGraphBox.setVisible(false);
                timeGraphBox.setVisible(false);
                dataGraphBox.setVisible(false);

                Map<String, ArrayList<String>> packetCount = pcap.createArrivalTimes(pcapList);
                Set<String> keys = packetCount.keySet();
                for (String tempKey : keys) {
                    timeData.add(new TimeTable(tempKey, packetCount.get(tempKey).get(0), packetCount.get(tempKey).get(1)));
                }

                timeIPCol.setCellValueFactory(new PropertyValueFactory<>("IPaddressProperty"));
                timeFirstCol.setCellValueFactory(new PropertyValueFactory<>("firstArrivalProperty"));
                timeLastCol.setCellValueFactory(new PropertyValueFactory<>("lastArrivalProperty"));
                timeView.setItems(timeData);
            } else {
                noFileError();
            }
        } else if (event.getSource() == dataBut) {
            if (pcapList != null) {
                loaded.setVisible(false);
                packetBox.setVisible(false);
                timeBox.setVisible(false);
                dataBox.setVisible(true);
                packetGraphBox.setVisible(false);
                timeGraphBox.setVisible(false);
                dataGraphBox.setVisible(false);

                Map<String, Integer> avgDataLength = pcap.createAvgDataLength(pcapList);
                Set<String> keys = avgDataLength.keySet();
                for (String tempKey : keys) {
                    dataData.add(new UsageTable(tempKey, avgDataLength.get(tempKey)));
                }

                dataIPCol.setCellValueFactory(new PropertyValueFactory<>("IPaddressProperty"));
                dataSizeCol.setCellValueFactory(new PropertyValueFactory<>("packetProperty"));
                dataView.setItems(dataData);
            } else {
                noFileError();
            }
        } else if (event.getSource() == packetGraphBut) {
            if (pcapList != null) {
                loaded.setVisible(false);
                packetBox.setVisible(false);
                timeBox.setVisible(false);
                dataBox.setVisible(false);
                packetGraphBox.setVisible(true);
                timeGraphBox.setVisible(false);
                dataGraphBox.setVisible(false);

                packetGraph.getData().clear();
                XYChart.Series set = new XYChart.Series<>();
                Map<String, Integer> packetCount = pcap.createPacketCount(pcapList);
                Map<String, Integer> top5Packet = pcap.getTopPacketSenders();
                top5Packet = sortByValue(top5Packet);
                Set<String> keys = top5Packet.keySet();
                for (String tempKey : keys) {
                    set.getData().add(new XYChart.Data(tempKey, top5Packet.get(tempKey)));
                }
                packetGraph.getData().addAll(set);
                packetGraph.setTitle("Top 5 Packet Senders");

            } else {
                noFileError();
            }
        } else if (event.getSource() == timeGraphBut) {
            if (pcapList != null) {
                loaded.setVisible(false);
                packetBox.setVisible(false);
                timeBox.setVisible(false);
                dataBox.setVisible(false);
                packetGraphBox.setVisible(false);
                timeGraphBox.setVisible(true);
                dataGraphBox.setVisible(false);

                timeGraph.getData().clear();
                XYChart.Series set = new XYChart.Series<>();
                Map<String, ArrayList<String>> arrivalTimes = pcap.createArrivalTimes(pcapList);
                Map<String, Long> top5Times = pcap.getTopTimes();
                top5Times = sortByValue(top5Times);
                Set<String> keys = top5Times.keySet();
                for (String tempKey : keys) {
                    set.getData().add(new XYChart.Data(tempKey, top5Times.get(tempKey)));
                }
                timeGraph.getData().addAll(set);
                timeGraph.setTitle("Top 5 IP's Connected the Longest (ms)");

            } else {
                noFileError();
            }
        } else if (event.getSource() == dataGraphBut) {
            if (pcapList != null) {
                loaded.setVisible(false);
                packetBox.setVisible(false);
                timeBox.setVisible(false);
                dataBox.setVisible(false);
                packetGraphBox.setVisible(false);
                timeGraphBox.setVisible(false);
                dataGraphBox.setVisible(true);

                dataGraph.getData().clear();
                XYChart.Series set = new XYChart.Series<>();
                Map<String, Integer> avgDataLength = pcap.createAvgDataLength(pcapList);
                Map<String, Integer> top5AvgData = pcap.getTopAvgDataLength();
                top5AvgData = sortByValue(top5AvgData);
                Set<String> keys = top5AvgData.keySet();
                for (String tempKey : keys) {
                    set.getData().add(new XYChart.Data(tempKey, top5AvgData.get(tempKey)));
                }
                dataGraph.getData().addAll(set);
                dataGraph.setTitle("Top 5 Data Senders on Avg (bytes)");
            } else {
                noFileError();
            }
        }
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        unloaded.setVisible(true);
        loaded.setVisible(false);
        packetBox.setVisible(false);
        timeBox.setVisible(false);
        dataBox.setVisible(false);
        packetGraphBox.setVisible(false);
        timeGraphBox.setVisible(false);
        dataGraphBox.setVisible(false);
    }
}
